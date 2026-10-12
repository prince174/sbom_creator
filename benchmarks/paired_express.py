"""Build paired reference/runtime evidence externally, with no oracle in analyzer inputs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import time

from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

WORK = ROOT / "benchmarks/.work/paired-express-v1"
OUT = ROOT / "benchmarks/references/paired-express-v1"
COMMIT = "1faf228935aa0a13111f92c28ee795be64ce3f0f"
IMAGE = "sbom-creator-benchmark/paired-express:v1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def application_tree(path):
    """Compare paths, modes, types, bytes and links; exclude time/owners/xattrs."""
    entries = []
    with tarfile.open(path) as archive:
        for member in archive:
            name = member.name.split("/", 1)[1] if "/" in member.name else ""
            if not name:
                continue
            value = {"path": name, "mode": member.mode, "type": member.type.decode(), "link": member.linkname}
            if member.isfile():
                with archive.extractfile(member) as stream:
                    value["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
            entries.append(value)
    entries.sort(key=lambda item: item["path"])
    return entries


def archive_binding(path, expected_index):
    """Verify OCI index -> platform manifest -> config, without conflating digests."""
    with tarfile.open(path) as archive:
        def blob(descriptor):
            digest = descriptor["digest"]
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                raise ValueError("Invalid OCI digest")
            raw = archive.extractfile("blobs/sha256/" + digest.split(":")[1]).read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024 or len(raw) != descriptor["size"] or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("OCI descriptor hash or size mismatch")
            return json.loads(raw)
        outer = json.load(archive.extractfile("index.json"))
        selected = [d for d in outer["manifests"] if d["digest"] == expected_index]
        if len(selected) != 1:
            raise ValueError("Runtime index absent or ambiguous")
        index = blob(selected[0])
        platforms = [d for d in index["manifests"] if d.get("platform", {}).get("os") == "linux" and d.get("platform", {}).get("architecture") == "amd64"]
        if len(platforms) != 1:
            raise ValueError("Platform manifest absent or ambiguous")
        manifest = blob(platforms[0])
        config = blob(manifest["config"])
        if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
            raise ValueError("Config platform mismatch")
        return {"index_digest": expected_index, "platform_manifest_digest": platforms[0]["digest"],
                "config_digest": manifest["config"]["digest"]}


def export_from_image(image, paths, label):
    container = subprocess.check_output(["docker", "create", image], text=True).strip()
    try:
        for remote, destination, tar_output in paths:
            if tar_output:
                with destination.open("wb") as output:
                    subprocess.run(["docker", "cp", f"{container}:{remote}", "-"], stdout=output, check=True, timeout=300)
            else:
                run_command(["docker", "cp", f"{container}:{remote}", str(destination)], WORK / f"{label}-copy.log")
    finally:
        subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL, timeout=30)


def main():
    global WORK, OUT, IMAGE
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume-validation", action="store_true")
    parser.add_argument("--run-id", default="v1", help="Fresh evidence namespace; completed receipts are immutable")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", args.run_id):
        raise ValueError("Invalid run ID")
    WORK = ROOT / "benchmarks/.work" / ("paired-express-" + args.run_id)
    OUT = ROOT / "benchmarks/references" / ("paired-express-" + args.run_id)
    IMAGE = "sbom-creator-benchmark/paired-express:" + args.run_id
    resume = args.resume_validation
    if (OUT / "receipt.json").exists():
        raise FileExistsError("Immutable R3 receipt exists; inspect it instead of duplicating this experiment")
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    source = WORK / "src"
    if not source.exists():
        run_command(["git", "clone", "--no-hardlinks", "--no-checkout", str(ROOT / "benchmarks/.work/javascript-express/src"), str(source)], WORK / "clone.log")
        run_command(["git", "-c", "core.autocrlf=false", "checkout", "--detach", COMMIT], WORK / "checkout.log", cwd=source)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != COMMIT:
        raise ValueError("Source commit mismatch")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip():
        raise ValueError("Source checkout modified")
    if resume:
        if sha(WORK / "Dockerfile") != sha(OUT / "Dockerfile") or sha(OUT / "Dockerfile") != sha(ROOT / "benchmarks/paired-express.Dockerfile"):
            raise ValueError("Recipe changed before validation resumed")
        builder = (WORK / "builder.id").read_text().strip()
        runtime = (WORK / "runtime.id").read_text().strip()
    else:
        shutil.copyfile(ROOT / "benchmarks/paired-express.Dockerfile", WORK / "Dockerfile")
        (WORK / ".dockerignore").write_text("**\n!Dockerfile\n!src/\n!src/**\nsrc/.git/\n", encoding="utf-8")
        start = time.monotonic()
        run_command(["docker", "build", "--platform", "linux/amd64", "--target", "build", "--iidfile", str(WORK / "builder.id"), "--progress=plain", str(WORK)], WORK / "build.log", timeout=1800)
        builder = (WORK / "builder.id").read_text().strip()
        export_from_image(builder, [("/reference/.", OUT, False), ("/src", WORK / "builder-app.tar", True)], "builder")
        run_command(["docker", "build", "--platform", "linux/amd64", "--target", "runtime", "--iidfile", str(WORK / "runtime.id"), "--progress=plain", "-t", IMAGE, str(WORK)], WORK / "runtime.log", timeout=1800)
        runtime = (WORK / "runtime.id").read_text().strip()
        export_from_image(runtime, [("/app", WORK / "runtime-app.tar", True)], "runtime")
    before, after = application_tree(WORK / "builder-app.tar"), application_tree(WORK / "runtime-app.tar")
    if before != after:
        raise ValueError("Runtime application differs from the environment used by CycloneDX")
    if any(e["path"].endswith("sbom.json") or e["path"].startswith(".git/") for e in after):
        raise ValueError("Unexpected reference or Git metadata in runtime application")
    document = json.loads((OUT / "sbom.json").read_bytes())
    validate_cyclonedx(document)
    package = json.loads((source / "package.json").read_bytes())
    declared = set(package.get("dependencies", {}))
    root = document["metadata"]["component"]["bom-ref"]
    direct = next(e["dependsOn"] for e in document["dependencies"] if e["ref"] == root)
    by_ref = {c["bom-ref"]: c for c in document["components"]}
    selected = [by_ref[ref] for ref in direct]
    if {c["name"] for c in selected} != declared or len(selected) != len(declared):
        raise ValueError("CycloneDX root graph differs from literal production dependencies")
    atomic_json(OUT / "application-tree.json", after)
    shutil.copyfile(source / "package.json", OUT / "package.json")
    shutil.copyfile(WORK / "Dockerfile", OUT / "Dockerfile")
    archive = WORK / "runtime-image.tar"
    result_dir = WORK / "analysis"
    if resume:
        summary = json.loads((result_dir / "summary.json").read_bytes())
        build_seconds = analysis_seconds = None
    else:
        build_seconds = time.monotonic() - start
        run_command(["docker", "image", "save", "-o", str(archive), runtime], WORK / "save.log", timeout=300)
        settings = Settings(syft_binary=str(ROOT / ".tools/syft/syft.exe"), registry_hosts=("docker.io",), image_archive=str(archive))
        start = time.monotonic()
        summary = analyze_local(source, "docker.io/" + IMAGE, result_dir, settings=settings, mode="rules")
        analysis_seconds = time.monotonic() - start
    analysis_provenance = json.loads((result_dir / "provenance.json").read_bytes())
    binding = archive_binding(archive, runtime)
    catalog = json.loads((result_dir / "image.syft.json").read_bytes())
    metadata = catalog["source"]["metadata"]
    config_raw = base64.b64decode(metadata["config"], validate=True)
    manifest_raw = base64.b64decode(metadata["manifest"], validate=True)
    if (analysis_provenance["image"]["image_config_digest"] != binding["config_digest"]
            or "sha256:" + hashlib.sha256(config_raw).hexdigest() != binding["config_digest"]
            or json.loads(manifest_raw)["config"]["digest"] != binding["config_digest"]
            or "sha256:" + hashlib.sha256(manifest_raw).hexdigest() != analysis_provenance["image"]["platform_digest"]):
        raise ValueError("Analyzer scanned a different image")
    binding["syft_archive_manifest_digest"] = analysis_provenance["image"]["platform_digest"]
    binding["note"] = "Docker archive scanner may synthesize a Docker manifest; bind using verified identical config bytes (including rootfs diff IDs), not equality with the OCI manifest digest"
    if any("cyclonedx" in a["name"].lower() for a in catalog["artifacts"]):
        raise ValueError("Reference generator leaked into runtime image")
    for filename, digest in analysis_provenance["input_hashes"].items():
        if sha(result_dir / filename) != digest:
            raise ValueError("Analyzer input evidence changed")
    for name in ("final.cdx.json", "os.cdx.json", "full.cdx.json"):
        validate_cyclonedx(json.loads((result_dir / name).read_bytes()))
    receipt = {"experiment": "R3", "project": "javascript-express", "commit": COMMIT,
               "repository_url": "https://github.com/expressjs/express.git", "platform": "linux/amd64",
               "builder_image": builder, "runtime_image": runtime, "runtime_config_digest": binding["config_digest"], "archive_binding": binding,
               "application_tree_equal": True, "application_entries": len(after), "application_tree_sha256": sha(OUT / "application-tree.json"),
               "reference_sha256": sha(OUT / "sbom.json"), "package_lock_sha256": sha(OUT / "package-lock.json"),
               "source_manifest_sha256": sha(OUT / "package.json"), "recipe_sha256": sha(OUT / "Dockerfile"),
               "reference_generator": "@cyclonedx/cyclonedx-npm@6.0.1", "runtime_scope": "npm production dependencies, scripts disabled, pack lifecycle",
               "declared_direct_count": len(declared), "reference_root_edges": len(direct),
               "reference_graph_matches_declarations": True, "oracle_passed_to_analyzer": False,
               "analyzer_inputs": ["clean source checkout at commit", "runtime image archive"],
               "build_seconds": round(build_seconds, 3) if build_seconds is not None else None, "analysis_seconds": round(analysis_seconds, 3) if analysis_seconds is not None else None,
               "timing_note": "Not recovered after validation resume" if resume else "Wall clock",
               "resource_metrics": None, "resource_metrics_reason": "Peak CPU/RSS not instrumented",
               "analysis_directory": result_dir.relative_to(ROOT).as_posix(), "summary": summary,
               "outputs": {name: sha(result_dir / name) for name in ("final.cdx.json", "os.cdx.json", "full.cdx.json", "source.syft.json", "image.syft.json", "provenance.json")},
               "direct_accuracy": None, "direct_accuracy_reason": "B0 inventory is not a direct dependency classifier"}
    atomic_json(OUT / "receipt.json", receipt)
    print(json.dumps({"paired": True, "direct_edges": len(direct), "summary": summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()

"""External paired Python holdout wheel/venv builds. No oracle enters analyzer inputs."""
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import tarfile
from email.parser import BytesParser

import paired_express as shared
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx


def verify_metadata(archive_path, bom, project_name, environment):
    installed = {}
    with tarfile.open(archive_path) as archive:
        for member in archive:
            if member.isfile() and member.name.endswith(".dist-info/METADATA"):
                metadata = BytesParser().parsebytes(archive.extractfile(member).read())
                name = canonicalize_name(metadata["Name"])
                if name in installed:
                    raise ValueError("Ambiguous installed distribution")
                installed[name] = metadata
    root = installed[project_name]
    requirements = [Requirement(r) for r in root.get_all("Requires-Dist", [])]
    active = {canonicalize_name(r.name) for r in requirements
              if r.marker is None or r.marker.evaluate(environment)}
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    direct = [by_ref[r] for r in shared.root_dependencies(bom)]
    if {canonicalize_name(c["name"]) for c in direct} != active:
        raise ValueError("Reference and native runtime declarations disagree")
    for component in direct:
        if component["version"] != installed[canonicalize_name(component["name"])]["Version"]:
            raise ValueError("Reference version mismatch")
    return {"root_version": root["Version"], "direct": [{"name": c["name"], "version": c["version"]} for c in direct],
            "conditional_requires_dist": [str(r) for r in requirements if r.marker is not None],
            "marker_environment": environment, "build_requirements_excluded": True}



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume-built-images", action="store_true")
    parser.add_argument("--project", choices=["flask", "packaging", "httpx"], required=True)
    args = parser.parse_args()
    frozen = "060f4d381c5c1fb332fcec598789caca960f6514c174a131d04f95fc1c9d214f"
    if shared.sha(ROOT / "benchmarks/python_direct_p1.py") != frozen:
        raise ValueError("P1 changed before control evaluation")
    WORK = ROOT / ("benchmarks/.work/paired-" + args.project + "-v1")
    OUT = ROOT / ("benchmarks/references/paired-" + args.project + "-v1")
    manifest = json.loads((ROOT / "benchmarks/manifest.json").read_bytes())
    entry = (json.loads((ROOT / "benchmarks/python-control-v2.json").read_bytes()) if args.project == "httpx"
             else next(p for p in manifest["repositories"] if p["id"] == "python-" + args.project))
    recipe = ROOT / ("benchmarks/paired-httpx.Dockerfile" if args.project == "httpx" else "benchmarks/paired-python.Dockerfile")
    if args.project == "httpx" and shared.sha(ROOT / "benchmarks/python_p1_guard.py") != entry["guard_sha256"]:
        raise ValueError("Guard changed before control evaluation")
    COMMIT = entry["commit"]
    if (OUT / "receipt.json").exists():
        raise FileExistsError("Immutable pair already exists")
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    shared.WORK = WORK
    source = WORK / "src"
    if not source.exists():
        run_command(["git", "clone", "--no-hardlinks", "--no-checkout", str(ROOT / ("benchmarks/.work/python-" + args.project + "/src")), str(source)], WORK / "clone.log")
        run_command(["git", "-c", "core.autocrlf=false", "checkout", "--detach", COMMIT], WORK / "checkout.log", cwd=source)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != COMMIT or subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip():
        raise ValueError("Checkout is not clean at requested commit")
    if args.resume_built_images and shared.sha(recipe) != shared.sha(WORK / "Dockerfile"):
        raise ValueError("Build recipe changed before resume")
    shutil.copyfile(recipe, WORK / "Dockerfile")
    (WORK / ".dockerignore").write_text("**\n!Dockerfile\n!src/\n!src/**\nsrc/.git/\n", encoding="utf-8")
    for stage in (() if args.resume_built_images else ("build", "runtime")):
        run_command(["docker", "build", "--platform", "linux/amd64", "--target", stage, "--iidfile", str(WORK / (stage + ".id")), "--progress=plain", "--build-arg", "PROJECT=" + args.project, str(WORK)], WORK / (stage + ".log"), timeout=1800)
        identity = (WORK / (stage + ".id")).read_text().strip()
        exports = [("/project", WORK / (stage + "-app.tar"), True)]
        if stage == "build":
            exports.append(("/reference/.", OUT, False))
        shared.export_from_image(identity, exports, stage)
    tree = shared.application_tree(WORK / "runtime-app.tar")
    if tree != shared.application_tree(WORK / "build-app.tar"):
        raise ValueError("Venv trees differ")
    bom = json.loads((OUT / "sbom.json").read_bytes())
    validate_cyclonedx(bom)
    evidence = verify_metadata(WORK / "runtime-app.tar", bom, args.project, json.loads((OUT / "marker-environment.json").read_bytes()))
    runtime = (WORK / "runtime.id").read_text().strip()
    archive = WORK / "image.tar"
    if not args.resume_built_images:
        run_command(["docker", "image", "save", "-o", str(archive), runtime], WORK / "save.log", timeout=300)
    analysis = WORK / "analysis"
    summary = analyze_local(source, "docker.io/sbom-creator-benchmark/paired-" + args.project + ":v1", analysis,
                            Settings(syft_binary=str(ROOT / ".tools/syft/syft.exe"), registry_hosts=("docker.io",), image_archive=str(archive)))
    binding = shared.archive_binding(archive, runtime)
    image = json.loads((analysis / "image.syft.json").read_bytes())
    config = base64.b64decode(image["source"]["metadata"]["config"], validate=True)
    if "sha256:" + hashlib.sha256(config).hexdigest() != binding["config_digest"]:
        raise ValueError("Wrong scanned image")
    if any("cyclonedx" in a["name"].lower() for a in image["artifacts"]):
        raise ValueError("Generator leaked into runtime")
    for name in ("final", "os", "full"):
        validate_cyclonedx(json.loads((analysis / (name + ".cdx.json")).read_bytes()))
    shutil.copyfile(WORK / "Dockerfile", OUT / "Dockerfile")
    shutil.copyfile(source / "pyproject.toml", OUT / "pyproject.toml")
    atomic_json(OUT / "application-tree.json", tree)
    atomic_json(OUT / "metadata-check.json", evidence)
    receipt = {"experiment": "R15" if args.project == "httpx" else "R13", "project": "python-" + args.project, "commit": COMMIT,
               "image_binding": binding, "venv_tree_equal": True, "reference_only_for_evaluation": True,
               "reference_hashes": {p.name: shared.sha(p) for p in OUT.iterdir() if p.is_file()},
               "outputs": {p.name: shared.sha(p) for p in analysis.iterdir() if p.is_file()},
               "summary": summary, "direct_precision": None, "direct_recall": None,
               "reason": "P1 evaluated separately; production runtime unchanged", "classifier_sha256": frozen, "peak_resources": None}
    atomic_json(OUT / "receipt.json", receipt)
    print(json.dumps({"metadata": evidence, "summary": summary}))


if __name__ == "__main__":
    main()

"""External Commons Text artifact-image build. No oracle enters analyzer inputs."""
import argparse
import base64
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

import paired_express as shared
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

WORK = ROOT / "benchmarks/.work/paired-commons-text-v1"
OUT = ROOT / "benchmarks/references/paired-commons-text-v1"
COMMIT = "9430a2848a2593ee3bce32750305c28c549cabf8"


def verify_metadata(archive_path, bom, native, effective):
    def coord(node):
        return (node["groupId"], node["artifactId"], node["version"])
    root = bom["metadata"]["component"]
    if (root.get("group"), root["name"], root["version"]) != coord(native):
        raise ValueError("Root owner mismatch")
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    expected = {(by_ref[r].get("group"), by_ref[r]["name"], by_ref[r]["version"]) for r in shared.root_dependencies(bom)}
    native_direct = {coord(c) for c in native.get("children", [])}
    if expected != native_direct:
        raise ValueError("CycloneDX/native direct graph mismatch")
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    pom = ET.fromstring(effective)
    direct = set()
    for dep in pom.findall("m:dependencies/m:dependency", ns):
        scope = dep.findtext("m:scope", default="compile", namespaces=ns)
        if scope in ("compile", "runtime"):
            direct.add(tuple(dep.findtext("m:" + key, namespaces=ns) for key in ("groupId", "artifactId", "version")))
    if direct != native_direct:
        raise ValueError("Effective POM/runtime graph mismatch")
    installed = set()
    with tarfile.open(archive_path) as archive:
        for member in archive:
            if member.isfile() and member.name.endswith(".jar"):
                with zipfile.ZipFile(io.BytesIO(archive.extractfile(member).read())) as jar:
                    for name in jar.namelist():
                        if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                            values = dict(line.split("=", 1) for line in jar.read(name).decode("utf-8").splitlines()
                                          if "=" in line and not line.startswith("#"))
                            installed.add(tuple(values[k] for k in ("groupId", "artifactId", "version")))
    if installed != native_direct | {coord(native)}:
        raise ValueError("JAR inventory differs from expected fixture")
    return {"root": coord(native), "direct": sorted(native_direct), "jar_coordinates": sorted(installed),
            "effective_pom_native_cyclonedx_agree": True, "scope": "compile/runtime; no tests", "accuracy_measured": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume-built-images", action="store_true")
    args = parser.parse_args()
    if (OUT / "receipt.json").exists():
        raise FileExistsError("Immutable pair already exists")
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    shared.WORK = WORK
    source = WORK / "src"
    if not source.exists():
        run_command(["git", "clone", "--no-hardlinks", "--no-checkout", str(ROOT / "benchmarks/.work/java-commons-text/src"), str(source)], WORK / "clone.log")
        run_command(["git", "-c", "core.autocrlf=false", "checkout", "--detach", COMMIT], WORK / "checkout.log", cwd=source)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != COMMIT or subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip():
        raise ValueError("Checkout is not clean at requested commit")
    if args.resume_built_images and shared.sha(ROOT / "benchmarks/paired-commons-text.Dockerfile") != shared.sha(WORK / "Dockerfile"):
        raise ValueError("Build recipe changed before resume")
    shutil.copyfile(ROOT / "benchmarks/paired-commons-text.Dockerfile", WORK / "Dockerfile")
    (WORK / ".dockerignore").write_text("**\n!Dockerfile\n!src/\n!src/**\nsrc/.git/\n", encoding="utf-8")
    for stage in (() if args.resume_built_images else ("build", "runtime")):
        run_command(["docker", "build", "--platform", "linux/amd64", "--target", stage, "--iidfile", str(WORK / (stage + ".id")), "--progress=plain", str(WORK)], WORK / (stage + ".log"), timeout=1800)
        identity = (WORK / (stage + ".id")).read_text().strip()
        exports = [("/application", WORK / (stage + "-app.tar"), True)]
        if stage == "build":
            exports.append(("/reference/.", OUT, False))
        shared.export_from_image(identity, exports, stage)
    tree = shared.application_tree(WORK / "runtime-app.tar")
    if tree != shared.application_tree(WORK / "build-app.tar"):
        raise ValueError("Artifact trees differ")
    bom = json.loads((OUT / "sbom.json").read_bytes())
    validate_cyclonedx(bom)
    evidence = verify_metadata(WORK / "runtime-app.tar", bom, json.loads((OUT / "dependency-tree.json").read_bytes()), (OUT / "effective-pom.xml").read_bytes())
    runtime = (WORK / "runtime.id").read_text().strip()
    archive = WORK / "image.tar"
    if not archive.exists():
        run_command(["docker", "image", "save", "-o", str(archive), runtime], WORK / "save.log", timeout=300)
    analysis = WORK / "analysis"
    summary = analyze_local(source, "docker.io/sbom-creator-benchmark/paired-commons-text:v1", analysis,
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
    shutil.copyfile(source / "pom.xml", OUT / "pom.xml")
    atomic_json(OUT / "application-tree.json", tree)
    atomic_json(OUT / "metadata-check.json", evidence)
    receipt = {"experiment": "R21", "project": "java-commons-text", "commit": COMMIT,
               "image_binding": binding, "artifact_tree_equal": True, "reference_only_for_evaluation": True,
               "reference_hashes": {p.name: shared.sha(p) for p in OUT.iterdir() if p.is_file()},
               "outputs": {p.name: shared.sha(p) for p in analysis.iterdir() if p.is_file()},
               "summary": summary, "direct_precision": None, "direct_recall": None,
               "reason": "Java direct classifier not implemented; artifact-only image has no JRE", "peak_resources": None}
    atomic_json(OUT / "receipt.json", receipt)
    print(json.dumps({"metadata": evidence, "summary": summary}))


if __name__ == "__main__":
    main()

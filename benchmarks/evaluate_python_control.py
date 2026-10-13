"""Frozen P1 control evaluation; reference used only after prediction."""
import base64
import hashlib
import json
import time
import tomllib

import packaging
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from paired_express import application_tree, archive_binding, sha
from paired_python import verify_metadata
from python_direct_p1 import classify
from run import ROOT

from sbom_creator.validation import validate_cyclonedx

FROZEN = "060f4d381c5c1fb332fcec598789caca960f6514c174a131d04f95fc1c9d214f"
SPLIT = "c5832b6f2fa146bb369f4d2e54033c9e2569572efe5dfe38b92c6c36a140d6e7"


def metrics(tp, fp, fn):
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def evaluate(project, classifier=classify):
    work = ROOT / ("benchmarks/.work/paired-" + project + "-v1")
    out = ROOT / ("benchmarks/references/paired-" + project + "-v1")
    source_path = work / "src/pyproject.toml"
    source = tomllib.loads(source_path.read_text("utf-8"))
    image_path = work / "analysis/image.syft.json"
    image = json.loads(image_path.read_bytes())
    started = time.perf_counter()
    prediction = classifier(source, image)
    elapsed = time.perf_counter() - started
    # Evaluation-only evidence begins here.
    receipt = json.loads((out / "receipt.json").read_bytes())
    for name, digest in receipt["reference_hashes"].items():
        if sha(out / name) != digest:
            raise ValueError("Reference changed")
    for name, digest in receipt["outputs"].items():
        if sha(work / "analysis" / name) != digest:
            raise ValueError("Analysis changed")
    if sha(source_path) != receipt["reference_hashes"]["pyproject.toml"]:
        raise ValueError("Source changed")
    tree = application_tree(work / "runtime-app.tar")
    if tree != application_tree(work / "build-app.tar") or tree != json.loads((out / "application-tree.json").read_bytes()):
        raise ValueError("Build/runtime tree mismatch")
    binding = archive_binding(work / "image.tar", receipt["image_binding"]["index_digest"])
    config = base64.b64decode(image["source"]["metadata"]["config"], validate=True)
    if binding != receipt["image_binding"] or "sha256:" + hashlib.sha256(config).hexdigest() != binding["config_digest"]:
        raise ValueError("Image mismatch")
    bom = json.loads((out / "sbom.json").read_bytes())
    validate_cyclonedx(bom)
    environment = json.loads((out / "marker-environment.json").read_bytes())
    required = {"implementation_name", "implementation_version", "os_name", "platform_machine", "platform_release",
                "platform_system", "platform_version", "python_full_version", "platform_python_implementation",
                "python_version", "sys_platform", "extra"}
    if set(environment) != required or environment["extra"] != "":
        raise ValueError("Incomplete native marker profile")
    evidence = verify_metadata(work / "runtime-app.tar", bom, project, environment)
    declared = [Requirement(r) for r in source["project"].get("dependencies", [])]
    active = {canonicalize_name(r.name): r for r in declared if r.marker is None or r.marker.evaluate(environment)}
    expected = {(canonicalize_name(c["name"]), c["version"]) for c in evidence["direct"]}
    if set(active) != {name for name, version in expected}:
        raise ValueError("Source/native/reference graph mismatch")
    for name, version in expected:
        if not active[name].specifier.contains(version):
            raise ValueError("Source/reference version mismatch")
    root_version = bom["metadata"]["component"].get("version")
    if root_version is not None and root_version != evidence["root_version"]:
        raise ValueError("Root version mismatch")
    for name in ("final", "os", "full"):
        validate_cyclonedx(json.loads((work / "analysis" / (name + ".cdx.json")).read_bytes()))
    actual = {(e["name"], e["version"]) for e in prediction["edges"] if e["status"] == "DIRECT"}
    result = metrics(len(actual & expected), len(actual - expected), len(expected - actual))
    unknown = sum(e["status"] == "UNKNOWN" for e in prediction["edges"])
    result.update({"project": "python-" + project, "commit": receipt["commit"],
                   "receipt_sha256": sha(out / "receipt.json"), "paired_image_verified": True,
                   "three_schemas_valid": True, "prediction": prediction, "unknown": unknown,
                   "declaration_coverage": len(actual) / len(declared) if declared else None,
                   "active_reference_coverage": len(actual & expected) / len(expected) if expected else None,
                   "reference_root_version": root_version, "installed_root_version": evidence["root_version"],
                   "inactive_source_requirements": [str(r) for r in declared if r.marker and not r.marker.evaluate(environment)],
                   "prediction_seconds": elapsed, "peak_resources": None,
                   "exact_version_matches": len(actual & expected), "summary": receipt["summary"]})
    return result


def main():
    if sha(ROOT / "benchmarks/python_direct_p1.py") != FROZEN or sha(ROOT / "benchmarks/direct-evaluation-split-v1.json") != SPLIT:
        raise ValueError("Frozen classifier or split changed")
    if packaging.__version__ != "26.3":
        raise ValueError("Evaluation packaging version changed")
    rows = [evaluate(project) for project in ("flask", "packaging")]
    report = {"experiment": "R13", "classifier_sha256": FROZEN, "split_sha256": SPLIT,
              "packaging_version": packaging.__version__, "partition": "original nonblinded holdout",
              "runtime_changed": False, "projects": rows,
              "aggregate": metrics(*(sum(r[k] for r in rows) for k in ("tp", "fp", "fn")))}
    (ROOT / "docs/python-p1-control-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

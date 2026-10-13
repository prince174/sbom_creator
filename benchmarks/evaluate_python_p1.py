"""Development evaluation of P1 on the paired Jinja artifacts."""
import json
import time
import tomllib

import packaging
from packaging.utils import canonicalize_name
from paired_express import root_dependencies, sha
from paired_jinja import OUT, WORK
from python_direct_p1 import classify
from run import ROOT


def main():
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    source = WORK / "src/pyproject.toml"
    image_path = WORK / "analysis/image.syft.json"
    if sha(source) != receipt["reference_hashes"]["pyproject.toml"] or sha(image_path) != receipt["outputs"]["image.syft.json"]:
        raise ValueError("Input evidence changed")
    start = time.perf_counter()
    prediction = classify(tomllib.loads(source.read_text("utf-8")), json.loads(image_path.read_bytes()))
    elapsed = time.perf_counter() - start
    # Oracle accessed only after pure prediction.
    if sha(OUT / "sbom.json") != receipt["reference_hashes"]["sbom.json"]:
        raise ValueError("Reference changed")
    bom = json.loads((OUT / "sbom.json").read_bytes())
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    expected = {(canonicalize_name(by_ref[r]["name"]), by_ref[r]["version"]) for r in root_dependencies(bom)}
    actual = {(e["name"], e["version"]) for e in prediction["edges"] if e["status"] == "DIRECT"}
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    report = {"experiment": "R12", "classifier_sha256": sha(ROOT / "benchmarks/python_direct_p1.py"),
              "packaging_version": packaging.__version__, "partition": "development", "project": "python-jinja",
              "source_sha256": sha(source), "image_sha256": sha(image_path), "receipt_sha256": sha(OUT / "receipt.json"),
              "tp": tp, "fp": fp, "fn": fn, "precision": tp / (tp + fp) if tp + fp else None,
              "recall": tp / (tp + fn) if tp + fn else None,
              "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
              "unknown": sum(e["status"] == "UNKNOWN" for e in prediction["edges"]),
              "coverage": len(actual) / len(expected) if expected else None,
              "prediction_seconds_with_input_parse": elapsed, "peak_resources": None,
              "root_version_accuracy": None, "holdout_evaluated": False, "runtime_changed": False,
              "prediction": prediction}
    (ROOT / "docs/python-p1-development-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

"""R4 development-only evaluator. Reference is loaded AFTER pure prediction."""
import hashlib
import json
import time
from pathlib import Path

from npm_direct_h1 import classify
from paired_express import OUT, WORK, sha
from run import ROOT


def main():
    source = WORK / "src/package.json"
    image = WORK / "analysis/image.syft.json"
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    if sha(source) != receipt["source_manifest_sha256"]:
        raise ValueError("Source changed")
    if sha(image) != receipt["outputs"]["image.syft.json"]:
        raise ValueError("Image evidence changed")
    if sha(OUT / "sbom.json") != receipt["reference_sha256"]:
        raise ValueError("Reference changed")
    start = time.perf_counter()
    prediction = classify(json.loads(source.read_bytes()), json.loads(image.read_bytes()))
    elapsed = time.perf_counter() - start
    # Evaluation boundary: the classifier receives neither reference nor build lock.
    reference = json.loads((OUT / "sbom.json").read_bytes())
    root = reference["metadata"]["component"]["bom-ref"]
    components = {c["bom-ref"]: c for c in reference["components"]}
    refs = next(d["dependsOn"] for d in reference["dependencies"] if d["ref"] == root)
    expected = {(components[r]["name"], components[r]["version"]) for r in refs}
    actual = {(e["name"], e["version"]) for e in prediction["edges"] if e["status"] == "DIRECT"}
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    report = {"experiment": "R4", "partition": "development", "projects": ["express"],
              "holdout_evaluated": False, "production_changed": False,
              "scope": "root production dependencies, owner package.json, exact name/version edges",
              "classifier_sha256": sha(Path(__file__).with_name("npm_direct_h1.py")),
              "source_sha256": sha(source), "image_sha256": sha(image),
              "reference_receipt_sha256": sha(OUT / "receipt.json"),
              "split_sha256": sha(ROOT / "benchmarks/direct-evaluation-split-v1.json"),
              "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall,
              "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
              "unknown": sum(e["status"] == "UNKNOWN" for e in prediction["edges"]),
              "coverage": len(actual) / len(prediction["edges"]) if prediction["edges"] else None,
              "prediction_seconds_including_json_load": elapsed, "peak_rss": None,
              "baseline_direct_metrics": None, "baseline_reason": "B0 does not classify direct edges",
              "prediction": prediction}
    output = ROOT / "docs/npm-h1-development-v1.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in report.items() if k != "prediction"}))
    print("report_sha256=" + hashlib.sha256(output.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()

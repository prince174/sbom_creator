"""Replay frozen paired inputs through the experimental bounded boundary."""
import json
import time
import tomllib

from evaluate_python_control import evaluate
from paired_express import sha
from python_p1_boundary import classify, load_manifest
from python_p1_guard import classify as guarded
from run import ROOT


def main():
    rows = []
    for project in ("jinja", "flask", "packaging", "httpx"):
        work = ROOT / ("benchmarks/.work/paired-" + project + "-v1")
        out = ROOT / ("benchmarks/references/paired-" + project + "-v1")
        receipt = json.loads((out / "receipt.json").read_bytes())
        source_path = work / "src/pyproject.toml"
        image_path = work / "analysis/image.syft.json"
        if sha(image_path) != receipt["outputs"]["image.syft.json"]:
            raise ValueError("Image input changed")
        loaded = load_manifest(work / "src")
        if loaded["status"] != "available" or loaded["sha256"] != receipt["reference_hashes"]["pyproject.toml"]:
            raise ValueError("Source not preserved by loader")
        source = tomllib.loads(source_path.read_text("utf-8"))
        if loaded["document"] != source:
            raise ValueError("Loader changed document")
        image = json.loads(image_path.read_bytes())
        start = time.perf_counter()
        prediction = classify(loaded["document"], image)
        elapsed = time.perf_counter() - start
        identical = prediction == guarded(source, image)
        row = {"project": project, "receipt_sha256": sha(out / "receipt.json"),
               "prediction_identical": identical, "status": prediction["status"],
               "reason": prediction.get("reason"), "seconds": elapsed, "peak_resources": None,
               "direct": sum(e["status"] == "DIRECT" for e in prediction["edges"]),
               "unknown": None if prediction["status"] == "UNKNOWN" else sum(e["status"] == "UNKNOWN" for e in prediction["edges"])}
        if project != "jinja":
            evaluation = evaluate(project, classifier=classify)
            row["control"] = {k: evaluation[k] for k in ("tp", "fp", "fn", "declaration_coverage", "reference_root_version")}
        rows.append(row)
    report = {"experiment": "R16", "runtime_changed": False, "accuracy_improvement_claimed": False, "adoption": "rejected: coverage regression",
              "boundary_sha256": sha(ROOT / "benchmarks/python_p1_boundary.py"), "rows": rows,
              "limitations": ["Existing control replay, not new blind sample", "No preparse Syft JSON budget here",
                              "Windows symlink creation test skipped", "No full memory/CPU benchmark"]}
    (ROOT / "docs/python-p1-boundary-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

"""Compare guarded and frozen P1 on immutable pairs and negative inputs."""
import json
import tomllib

from audit_python_p1_inputs import audit, cases
from evaluate_python_control import evaluate
from paired_express import sha
from python_direct_p1 import classify as frozen
from python_p1_guard import classify as guarded
from run import ROOT


def main():
    baseline = audit()
    rows = []
    for project in ("jinja", "flask", "packaging"):
        work = ROOT / ("benchmarks/.work/paired-" + project + "-v1")
        out = ROOT / ("benchmarks/references/paired-" + project + "-v1")
        receipt = json.loads((out / "receipt.json").read_bytes())
        source_path = work / "src/pyproject.toml"
        image_path = work / "analysis/image.syft.json"
        assert sha(source_path) == receipt["reference_hashes"]["pyproject.toml"]
        assert sha(image_path) == receipt["outputs"]["image.syft.json"]
        source = tomllib.loads(source_path.read_text("utf-8"))
        image = json.loads(image_path.read_bytes())
        result = guarded(source, image)
        assert result == frozen(source, image)
        rows.append({"project": project, "prediction_identical": True,
                     "receipt_sha256": sha(out / "receipt.json"),
                     "direct": sum(e["status"] == "DIRECT" for e in result["edges"]),
                     "unknown": sum(e["status"] == "UNKNOWN" for e in result["edges"])})
    negative = []
    for name, source, image in cases():
        result = guarded(source, image)
        if name != "valid":
            assert result["status"] == "UNKNOWN" and not result["edges"]
        negative.append({"case": name, "status": result["status"]})
    controls = [evaluate(p) for p in ("flask", "packaging")]
    report = {"experiment": "R14", "baseline": baseline, "guard_sha256": sha(ROOT / "benchmarks/python_p1_guard.py"),
              "pairs": rows, "guard_cases": negative, "runtime_changed": False,
              "control_metrics": [{k: r[k] for k in ("project", "tp", "fp", "fn", "unknown", "declaration_coverage")} for r in controls],
              "accuracy_improvement_claimed": False, "production_ready": False}
    (ROOT / "docs/python-p1-guard-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"pairs": rows, "baseline_exceptions": baseline["exception_count"], "guard_exceptions": 0}))


if __name__ == "__main__":
    main()

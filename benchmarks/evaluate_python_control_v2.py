"""Additional frozen P1 control; no tuning on this project."""
import json

import packaging
from evaluate_python_control import evaluate
from paired_express import sha
from python_p1_guard import classify
from run import ROOT


def main():
    selection_path = ROOT / "benchmarks/python-control-v2.json"
    selection = json.loads(selection_path.read_bytes())
    for filename, key in (("python_direct_p1.py", "classifier_sha256"), ("python_p1_guard.py", "guard_sha256")):
        if sha(ROOT / "benchmarks" / filename) != selection[key]:
            raise ValueError("Frozen rule changed")
    if packaging.__version__ != "26.3":
        raise ValueError("Evaluator dependency changed")
    baseline = evaluate("httpx")
    guarded = evaluate("httpx", classifier=classify)
    if baseline["prediction"] != guarded["prediction"]:
        raise ValueError("Guard changed control prediction")
    if guarded["commit"] != selection["commit"]:
        raise ValueError("Wrong selected commit")
    report = {"experiment": "R15", "selection_sha256": sha(selection_path), "selection": selection,
              "packaging_version": packaging.__version__, "runtime_changed": False,
              "guard_prediction_identical": True, "result": guarded,
              "limitation": "Purposive additional project; source cache existed before selection; not proven blind"}
    (ROOT / "docs/python-p1-control-v2.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

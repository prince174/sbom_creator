"""Negative input audit of frozen P1; does not change classification rules."""
import copy
import json

from paired_express import sha
from python_direct_p1 import classify
from run import ROOT
from test_python_direct_p1 import fixture

FROZEN = "060f4d381c5c1fb332fcec598789caca960f6514c174a131d04f95fc1c9d214f"


def cases():
    mutations = [
        ("valid", "none", None),
        ("project_array", "project", []),
        ("project_name_integer", "project.name", 42),
        ("dynamic_integer", "project.dynamic", 42),
        ("dependency_integer", "project.dependencies", [42]),
        ("dependencies_string", "project.dependencies", "dep>=2"),
        ("artifacts_null", "artifacts", None),
        ("artifact_null", "artifacts.0", None),
        ("metadata_null", "artifacts.0.metadata", None),
        ("requires_dist_null", "artifacts.0.metadata.requiresDist", None),
        ("requires_dist_integer", "artifacts.0.metadata.requiresDist", [42]),
        ("locations_null", "artifacts.1.locations", None),
        ("location_null", "artifacts.1.locations.0", None),
        ("path_null", "artifacts.1.locations.0.path", None),
        ("version_null", "artifacts.1.version", None),
        ("id_null", "artifacts.1.id", None),
        ("duplicate_id", "artifacts.1.id", "app"),
    ]
    for name, path, value in mutations:
        source, image = fixture()
        if path != "none":
            parts = path.split(".")
            target = source if parts[0] == "project" else image
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            key = int(parts[-1]) if isinstance(target, list) else parts[-1]
            target[key] = value
        yield name, source, image


def audit():
    if sha(ROOT / "benchmarks/python_direct_p1.py") != FROZEN:
        raise ValueError("Frozen P1 changed")
    rows = []
    for name, source, image in cases():
        before = copy.deepcopy((source, image))
        try:
            prediction = classify(source, image)
            direct = [e for e in prediction["edges"] if e["status"] == "DIRECT"]
            outcome = "DIRECT" if direct else "UNKNOWN"
            exception = None
        except (AttributeError, TypeError, KeyError, ValueError) as exc:
            outcome, exception = "exception", type(exc).__name__
        if (source, image) != before:
            raise AssertionError("Classifier mutated input")
        rows.append({"case": name, "outcome": outcome, "exception_type": exception,
                     "synthetic": True, "production_reachability_proven": False})
    return {"experiment": "R14", "classifier_sha256": FROZEN, "runtime_changed": False,
            "purpose": "robustness audit, not dependency accuracy", "cases": rows,
            "exception_count": sum(r["outcome"] == "exception" for r in rows),
            "invalid_direct_count": sum(r["outcome"] == "DIRECT" and r["case"] != "valid" for r in rows)}


if __name__ == "__main__":
    report = audit()
    (ROOT / "docs/python-p1-input-audit-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))

"""Read-only baseline assessment. Presence labels are not direct-dependency truth."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate():
    native_path = ROOT / "docs/native-golden-syft-v0.5.json"
    corpus_path = ROOT / "docs/verification-direct-syft-60.json"
    native, corpus = read(native_path), read(corpus_path)
    assert native["complete"] and corpus["complete"]
    labels_rows = []
    for row in native["rows"]:
        directory = Path(row["analysis_directory"])
        final = directory / "final.cdx.json"
        assert digest(final) == row["final_sha256"]
        truth = directory.parent / "ground-truth.json"
        assert digest(truth) == row["ground_truth_sha256"]
        ground_truth = read(truth)
        positive, negative = set(ground_truth["positive"]), set(ground_truth["negative"])
        assert not positive & negative
        observed = {c.get("purl") for c in read(final)["components"]}
        tp, fp, fn, tn = len(positive & observed), len(negative & observed), len(positive - observed), len(negative - observed)
        labels_rows.append({"language": row["language"], "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                           "unlabelled_final_identities": len(observed - positive - negative)})
    totals = {key: sum(r[key] for r in labels_rows) for key in ("tp", "fp", "fn", "tn", "unlabelled_final_identities")}
    totals.update(precision=totals["tp"]/(totals["tp"]+totals["fp"]),
                  recall=totals["tp"]/(totals["tp"]+totals["fn"]),
                  f1=2*totals["tp"]/(2*totals["tp"]+totals["fp"]+totals["fn"]))
    counts = Counter()
    corpus_rows = []
    for row in corpus["rows"]:
        directory = Path(row["analysis_directory"])
        final = directory / "final.cdx.json"
        assert digest(final) == row["final_sha256"]
        summary = read(directory / "summary.json")
        counts.update(d["decision"] for d in read(directory / "decisions.json"))
        document = read(final)
        coverage = read(directory / "coverage.json")
        corpus_rows.append({"id": row["id"], "language": row["language"],
            "non_os_records": len(document["components"]), "os_records": summary["os_count"],
            "full_records": summary["full_count"],
            "declared_dependency_graph_complete": coverage.get("dependency_graph_complete"),
            "subject_type": document.get("metadata", {}).get("component", {}).get("type"),
            "dependency_entries": len(document.get("dependencies", [])),
            "final_sha256": digest(final)})
    return {"schema_version": 1, "evaluated_at": "2026-10-13",
        "implementation_commit": "20f287b60d358692c843526704cd44e71ed4012f",
        "evaluation_checkout": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "service_version": "0.5.0", "evaluation_kind": "recomputed_from_frozen_outputs_not_new_scans",
        "direct_dependencies": {"status": "not_evaluated", "precision": None, "recall": None, "f1": None,
            "matched_build_cyclonedx_references": 0,
            "reason": "No paired build-generated CycloneDX reference was identified in benchmark/workspace directories; presence labels cannot evaluate direct edges."},
        "controlled_component_presence": {"scope": "Only explicit positive/negative presence labels; not direct dependency accuracy",
            "totals": totals, "by_language": labels_rows},
        "corpus": {"repositories": len(corpus_rows), "decisions": dict(counts),
            "decision_coverage": counts["INCLUDE"]/sum(counts.values()),
            "decision_coverage_is_accuracy": False,
            "non_os_records": sum(r["non_os_records"] for r in corpus_rows),
            "os_records": sum(r["os_records"] for r in corpus_rows),
            "full_records": sum(r["full_records"] for r in corpus_rows), "rows": corpus_rows},
        "evidence_sha256": {native_path.name: digest(native_path), corpus_path.name: digest(corpus_path)}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Preserve existing baseline; choose another output")
    result = evaluate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(result, ensure_ascii=False, indent=2)+"\n").encode())
    print(json.dumps({k: v for k,v in result.items() if k not in ("corpus",)}, ensure_ascii=False, indent=2))
    print("Corpus:", {k:v for k,v in result["corpus"].items() if k!="rows"})

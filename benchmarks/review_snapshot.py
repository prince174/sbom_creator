"""Group an existing audited run without changing decisions or SBOM artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbom_creator.core import review_report


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(report_path, output, summary_path):
    if output.exists() or summary_path.exists():
        raise FileExistsError("Choose fresh paths; preserve previous reports")
    report_hash = digest(report_path)
    report = json.loads(report_path.read_bytes())
    audit_path = report_path.with_name("audit-final.json")
    audit = json.loads(audit_path.read_bytes())
    assert audit["audit_passed"] and audit["snapshot_sha256"] == report_hash
    output.mkdir(parents=True)
    groups, reasons, observations = Counter(), Counter(), Counter()
    rows = []
    for row in report["repositories"]:
        assert row["status"] == "completed_rules"
        directory = Path(row["analysis_directory"])
        decisions_path, final_path = directory / "decisions.json", directory / "final.cdx.json"
        decisions_hash, final_hash = digest(decisions_path), digest(final_path)
        assert final_hash == row["final_sha256"]
        decisions = json.loads(decisions_path.read_bytes())
        previous = json.loads((directory / "review.json").read_bytes())
        assert review_report(decisions, schema_version=previous["schema_version"]) == previous
        current = review_report(decisions)
        assert current["unknown_count"] == previous["unknown_count"] == row["unknown"]
        assert current["reason_counts"] == previous["reason_counts"]
        assert sum(current["group_counts"].values()) == current["unknown_count"]
        path = output / (row["id"] + ".review.json")
        path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        groups.update(current["group_counts"])
        reasons.update(current["reason_counts"])
        observations.update(current["observation_counts"])
        assert digest(decisions_path) == decisions_hash and digest(final_path) == final_hash
        rows.append({"id": row["id"], "language": row["language"], "unknown": current["unknown_count"],
                     "group_counts": current["group_counts"], "final_sha256": final_hash,
                     "decisions_sha256": decisions_hash, "review_sha256": digest(path), "review_path": str(path)})
    assert digest(report_path) == report_hash
    summary = {"passed": True, "report_sha256": report_hash, "audit_sha256": digest(audit_path),
               "repositories": len(rows), "unknown": sum(groups.values()), "group_counts": dict(groups),
               "reason_counts": dict(reasons), "observation_counts": dict(observations), "rows": rows,
               "scope": "Review enrichment only; existing decisions and final SBOM bytes unchanged. No new scans or accuracy claims."}
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {k: v for k, v in summary.items() if k != "rows"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(snapshot(args.report.resolve(), args.output.resolve(), args.summary.resolve()), indent=2))

"""Export OS/non-OS views of a frozen audited inventory; no new scan or build."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbom_creator.exporter import split_inventory, validate_inventory_views


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(report_path, output, summary_path, archive_path):
    if any(p.exists() for p in (output, summary_path, archive_path)):
        raise FileExistsError("Use fresh paths; preserve earlier evidence")
    raw_report = report_path.read_bytes()
    report = json.loads(raw_report)
    audit = json.loads(report_path.with_name("audit-final.json").read_bytes())
    assert audit["audit_passed"] and audit["snapshot_sha256"] == digest(raw_report)
    output.mkdir(parents=True)
    rows, totals = [], Counter()
    for row in report["repositories"]:
        assert row["status"] == "completed_rules"
        directory = Path(row["analysis_directory"])
        raw_full = (directory / "final.cdx.json").read_bytes()
        assert digest(raw_full) == row["final_sha256"]
        full = json.loads(raw_full)
        selected = json.loads((directory / "selected.syft.json").read_bytes())
        application, os_packages = split_inventory(full, selected)
        validate_inventory_views(full, application, os_packages, selected)
        counts = {"non_os": len(application["components"]), "os": len(os_packages["components"]), "full": len(full["components"])}
        assert counts["non_os"] + counts["os"] == counts["full"]
        case = output / row["id"]
        case.mkdir()
        (case / "full.cdx.json").write_bytes(raw_full)
        for name, document in (("final.cdx.json", application), ("os.cdx.json", os_packages)):
            (case / name).write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
        hashes = {p.name: digest(p.read_bytes()) for p in case.iterdir()}
        assert digest((directory / "final.cdx.json").read_bytes()) == row["final_sha256"]
        rows.append({"id": row["id"], "language": row["language"], **counts, "output": str(case), "sha256": hashes})
        totals.update(counts)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    expected = {}
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            for name, sha in row["sha256"].items():
                relative = row["id"] + "/" + name
                data = (Path(row["output"]) / name).read_bytes()
                assert digest(data) == sha
                archive.writestr(relative, data)
                expected[relative] = sha
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.testzip() is None
        assert set(archive.namelist()) == set(expected)
        assert all(digest(archive.read(name)) == sha for name, sha in expected.items())
    summary = {"passed": True, "repositories": len(rows), "report_sha256": digest(raw_report),
               "counts": dict(totals), "rows": rows, "archive": str(archive_path),
               "archive_sha256": digest(archive_path.read_bytes()), "zip_crc_and_hashes_valid": True,
               "scope": "Export-only partition of audited 0.3.0 inventories. No new scans; project build usage is not established."}
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {k: v for k, v in summary.items() if k != "rows"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.report.resolve(), args.output.resolve(), args.summary.resolve(), args.archive.resolve()), indent=2))

"""Rescan frozen test images through Syft, compare all selection decisions and exports.
Docker is used only by this external fixture harness to export existing images.
The service receives an archive and cannot access the daemon.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from sbom_creator.acquire import Settings
from sbom_creator.core import rules_assessor
from sbom_creator.pipeline import publish_catalogs, sha256, write_json
from sbom_creator.scanner import scan_image


def run(report, work, receipt, syft):
    if work.exists() or receipt.exists():
        raise FileExistsError("Use fresh evidence paths")
    work.mkdir(parents=True)
    baseline = json.loads(report.read_bytes())
    rows = []
    for row in baseline["repositories"]:
        old = Path(row["analysis_directory"])
        assert sha256(old / "final.cdx.json") == row["final_sha256"]
        case = work / row["id"]
        case.mkdir()
        archive = case / "fixture.tar"
        subprocess.run(["docker", "image", "save", "-o", str(archive), row["image_id"]], check=True, timeout=300)
        settings = Settings(syft_binary=syft, registry_hosts=("docker.io",), image_archive=str(archive))
        try:
            image, provenance = scan_image("docker.io/" + row["image_reference"].removeprefix("docker.io/"), case / "image.json", settings)
            previous = json.loads((old / "provenance.json").read_bytes())
            assert provenance["image_config_digest"] == previous["image"]["image_config_digest"]
            previous["image"] = provenance
            source = json.loads((old / "source.syft.json").read_bytes())
            summary = publish_catalogs(source, image, case / "result", settings, rules_assessor, previous)
            decisions = json.loads((case / "result/decisions.json").read_bytes())
            old_decisions = json.loads((old / "decisions.json").read_bytes())
            def decision_set(items):
                return sorted((d["identity"], d["decision"], d.get("review_reason")) for d in items)
            def packages(document):
                return Counter((c.get("purl"), c.get("name"), c.get("version")) for c in document["components"])
            before = packages(json.loads((old / "final.cdx.json").read_bytes()))
            after = packages(json.loads((case / "result/full.cdx.json").read_bytes()))
            equal = decision_set(decisions) == decision_set(old_decisions)
            result = {"id": row["id"], "language": row["language"], "passed": equal and before == after,
                      "decisions_equal": equal, "full_components_equal": before == after,
                      "final_count": summary["final_count"], "os_count": summary["os_count"],
                      "full_count": summary["full_count"], "analysis_directory": str(case / "result"),
                      "final_sha256": sha256(case / "result/final.cdx.json")}
        except Exception as error:  # noqa: BLE001 -- sanitized failure receipt
            result = {"id": row["id"], "language": row["language"], "passed": False, "error": type(error).__name__}
        rows.append(result)
        write_json(receipt, {"passed": len(rows) == 60 and all(r["passed"] for r in rows),
            "complete": len(rows) == 60, "baseline_sha256": sha256(report),
            "scope": "60 existing test images rescanned via explicit archives; source inventories reused; no new builds",
            "rows": rows})
        print(row["id"], result["passed"], result.get("error", ""), flush=True)
        # Only this harness-created regular file is removed, never old evidence.
        archive.unlink()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--syft", required=True)
    args = parser.parse_args()
    run(args.report.resolve(), args.work.resolve(), args.receipt.resolve(), args.syft)

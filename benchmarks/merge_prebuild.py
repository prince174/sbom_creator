"""Merge a finished per-case native build checkpoint without losing later analysis."""
import argparse
import json
from pathlib import Path

from run import render_reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results" / "run-20260929")
    parser.add_argument("--language", required=True)
    args = parser.parse_args()
    source = json.loads((args.from_output / "results.json").read_text(encoding="utf-8"))
    target = json.loads((args.output / "results.json").read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in source["repositories"] if row["language"] == args.language and row["status"] != "pending"}
    rows = []
    for old in target["repositories"]:
        new = by_id.get(old["id"])
        if new and (new.get("image_id") != old.get("image_id") or old["stage"] in (None, "checkout", "source_scan", "native_image_build")):
            rows.append(new)
            print(new["id"], new["status"])
        else:
            rows.append(old)
    render_reports(rows, args.output)


if __name__ == "__main__":
    main()

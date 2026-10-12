"""Freeze a stratified development/holdout partition before H1 implementation."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = "sbom-direct-v1-pre-H1"


def partition(rows):
    development, holdout = [], []
    for language in sorted({r["language"] for r in rows}):
        candidates = sorted([r for r in rows if r["language"] == language],
                            key=lambda r: hashlib.sha256((SEED + r["id"]).encode()).hexdigest())
        eligible = [r for r in candidates if r["id"] != "javascript-express"]
        positive = next(r for r in eligible if r["direct_edges"] > 0)
        remaining = [r for r in eligible if r != positive]
        second = next((r for r in remaining if r["direct_edges"] == 0), remaining[0])
        selected = {positive["id"], second["id"]}
        holdout.extend(sorted(selected))
        development.extend(sorted(r["id"] for r in candidates if r["id"] not in selected))
    return {"development": sorted(development), "holdout": sorted(holdout)}


def main():
    source = ROOT / "benchmarks/references/build-v1/index.json"
    destination = ROOT / "benchmarks/direct-evaluation-split-v1.json"
    rows = json.loads(source.read_bytes())["projects"]
    split = partition(rows)
    document = {"schema_version": 1, "seed": SEED, "purpose": "fixed evaluation membership before H1 tuning",
                "source_index_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "protocol": "2 holdout projects per language: one nonempty root and one empty root when available; deterministic SHA256 order; express preassigned to development for R3",
                "limitations": ["Not blinded: R1/R2 artifacts were already inspected before partitioning",
                                "Ruby has only one nonempty project (psych), assigned to holdout; development needs additional independent positive fixtures before Ruby tuning",
                                "Do not tune rules on holdout; zero-positive projects must not inflate precision/recall"],
                **split}
    if destination.exists() and json.loads(destination.read_bytes()) != document:
        raise ValueError("Frozen partition would change")
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print({key: len(value) for key, value in split.items()})


if __name__ == "__main__":
    main()

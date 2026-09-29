"""Summarize saved UNKNOWN evidence without changing any decision or artifact."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def triage(report: Path, output: Path):
    rows = json.loads(report.read_bytes())["repositories"]
    groups = {}
    reasons, languages = Counter(), Counter()
    for row in rows:
        decisions = json.loads((Path(row["analysis_directory"]) / "decisions.json").read_bytes())
        unresolved = [d for d in decisions if d["decision"] == "UNKNOWN"]
        assert len(unresolved) == row["unknown"]
        for decision in unresolved:
            reason = decision["review_reason"]
            catalogers = tuple(sorted({e["artifact"]["foundBy"] for e in decision["evidence"]}))
            problem = decision["identity_problem"]
            key = (reason, problem, catalogers)
            group = groups.setdefault(key, {"reason": reason, "identity_problem": problem,
                "catalogers": list(catalogers), "count": 0, "languages": Counter(), "examples": []})
            group["count"] += 1
            group["languages"][row["language"]] += 1
            reasons[reason] += 1
            languages[row["language"]] += 1
            if len(group["examples"]) < 3:
                group["examples"].append({"repository": row["id"], "identity": decision["identity"],
                    "observations": [{"origin": e["origin"], "type": e["artifact"].get("type"),
                        "name": e["artifact"]["name"], "version": e["artifact"].get("version")}
                        for e in decision["evidence"][:3]]})
    result = {"input_report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "repositories": len(rows), "unknown": sum(reasons.values()), "reasons": dict(reasons),
        "languages": dict(languages), "groups": sorted(groups.values(), key=lambda g: -g["count"]),
        "scope": "Observed uncertainty causes only; no absence, FP/FN, or runtime-use labels inferred."}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = triage(args.report, args.output)
    print(json.dumps({k: v for k, v in result.items() if k != "groups"}, indent=2))

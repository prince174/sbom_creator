"""Development-only differential check against pinned upstream node-semver."""
import hashlib
import itertools
import json
import subprocess
from pathlib import Path

from npm_direct_h1 import satisfies as baseline
from npm_range_h2 import satisfies as candidate
from run import ROOT


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    oracle = ROOT / "benchmarks/.work/semver-oracle-v1"
    module = oracle / "node_modules/semver"
    if json.loads((module / "package.json").read_bytes())["version"] != "7.7.2":
        raise ValueError("Wrong oracle version")
    versions = [".".join(map(str, v)) for v in itertools.product(range(4), repeat=3)]
    cases = [(v, op + low) for v in versions for low in versions for op in ("", "~", "^")]
    script = "const fs=require('fs'),s=require(process.argv[1]);const c=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(c.map(([v,r])=>s.satisfies(v,r))));"
    result = subprocess.run(["node", "-e", script, str(module)], input=json.dumps(cases),
                            text=True, capture_output=True, check=True, timeout=60)
    expected = json.loads(result.stdout)
    if len(expected) != len(cases):
        raise ValueError("Incomplete oracle output")
    mismatches = []
    old_unknown = 0
    for (version, spec), truth in zip(cases, expected, strict=True):
        predicted = candidate(version, spec)
        old = baseline(version, spec)
        old_unknown += old is None
        if predicted is not truth or (old is not None and old is not truth):
            mismatches.append({"version": version, "range": spec, "expected": truth,
                               "candidate": predicted, "baseline": old})
    evidence = ROOT / "benchmarks/references/npm-range-oracle-v1"
    evidence.mkdir(exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        target = evidence / name
        raw = (oracle / name).read_bytes()
        if target.exists() and target.read_bytes() != raw:
            raise ValueError("Immutable oracle lock changed")
        target.write_bytes(raw)
    report = {"experiment": "R6", "scope": "synthetic stable npm range semantics, not SBOM accuracy",
              "oracle": "node-semver@7.7.2", "node_version": subprocess.check_output(["node", "--version"], text=True).strip(),
              "oracle_lock_sha256": digest(evidence / "package-lock.json"),
              "candidate_sha256": digest(Path(__file__).with_name("npm_range_h2.py")),
              "baseline_sha256": digest(Path(__file__).with_name("npm_direct_h1.py")),
              "generator": "all version and lower-bound triples in {0,1,2,3}^3 crossed with exact, tilde, caret",
              "cases": len(cases), "oracle_true": sum(expected), "oracle_false": len(expected) - sum(expected),
              "baseline_unknown": old_unknown, "candidate_unknown": sum(candidate(*c) is None for c in cases),
              "mismatches": mismatches, "project_inputs_used": False, "holdout_used": False,
              "direct_precision": None, "direct_recall": None, "runtime_changed": False}
    (ROOT / "docs/npm-range-development-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))
    if mismatches:
        raise SystemExit("Differential check failed")


if __name__ == "__main__":
    main()

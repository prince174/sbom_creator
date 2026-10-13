"""Compare H1/H2 on disclosed pairs only; the new control is not read."""
import json

from npm_direct_h1 import classify as baseline
from npm_direct_h2 import classify as candidate
from paired_express import root_dependencies, sha
from run import ROOT

from sbom_creator.validation import validate_cyclonedx


def main():
    rows = []
    for key in ("paired-express-v1", "paired-axios-v2", "paired-isarray-v1"):
        work = ROOT / "benchmarks/.work" / key
        out = ROOT / "benchmarks/references" / key
        receipt = json.loads((out / "receipt.json").read_bytes())
        for name, digest in receipt["outputs"].items():
            if sha(work / "analysis" / name) != digest:
                raise ValueError("Analysis evidence changed")
        if sha(work / "src/package.json") != receipt["source_manifest_sha256"]:
            raise ValueError("Source changed")
        if sha(out / "sbom.json") != receipt["reference_sha256"]:
            raise ValueError("Reference changed")
        package = json.loads((work / "src/package.json").read_bytes())
        image = json.loads((work / "analysis/image.syft.json").read_bytes())
        predictions = {"H1.1": baseline(package, image), "H2.1": candidate(package, image)}
        # Evaluation-only oracle is read after predictions have been produced.
        reference = json.loads((out / "sbom.json").read_bytes())
        validate_cyclonedx(reference)
        components = {c["bom-ref"]: c for c in reference.get("components", [])}
        expected = {(components[r]["name"], components[r]["version"]) for r in root_dependencies(reference)}
        scores = {}
        for version, prediction in predictions.items():
            actual = {(e["name"], e["version"]) for e in prediction["edges"] if e["status"] == "DIRECT"}
            tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
            scores[version] = {"tp": tp, "fp": fp, "fn": fn,
                               "precision": tp / (tp + fp) if tp + fp else None,
                               "recall": tp / (tp + fn) if tp + fn else None,
                               "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
                               "unknown": sum(e["status"] == "UNKNOWN" for e in prediction["edges"]),
                               "prediction": prediction}
        for name in ("final", "os", "full"):
            validate_cyclonedx(json.loads((work / "analysis" / (name + ".cdx.json")).read_bytes()))
        rows.append({"pair": key, "reference_receipt_sha256": sha(out / "receipt.json"),
                     "scope": "root production, exact name/version, owner package.json", "scores": scores})
    report = {"experiment": "R7", "partition": "disclosed regression; not independent control",
              "production_changed": False, "new_control_evaluated": False,
              "hashes": {name: sha(ROOT / "benchmarks" / name) for name in
                         ("npm_direct_h1.py", "npm_direct_h2.py", "npm_range_h2.py", "npm-control-v2.json")},
              "rows": rows}
    (ROOT / "docs/npm-h2-regression-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({r["pair"]: {v: {k: val for k, val in s.items() if k != "prediction"}
                                 for v, s in r["scores"].items()} for r in rows}))


if __name__ == "__main__":
    main()

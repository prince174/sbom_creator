"""Development-only gate measurement; no direct accuracy claim."""
import json

from java_scope_j1 import scope_candidates
from paired_commons_text import OUT, WORK
from paired_express import sha
from run import ROOT


def main():
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    pom = WORK / "src/pom.xml"
    if sha(pom) != receipt["reference_hashes"]["pom.xml"]:
        raise ValueError("Source changed")
    prediction = scope_candidates(pom.read_bytes())
    # Reference is inspected only after prediction; it is never a gate input.
    reference = OUT / "sbom.json"
    if sha(reference) != receipt["reference_hashes"]["sbom.json"]:
        raise ValueError("Reference changed")
    report = {"experiment": "R23", "project": "java-commons-text", "partition": "development",
              "pom_sha256": sha(pom), "reference_sha256": sha(reference),
              "prediction": prediction, "runtime_changed": False, "holdout_read": False,
              "direct_precision": None, "direct_recall": None, "version_accuracy": None,
              "reason": "Scope gate only, no owner/GAV classifier; unresolved model blocks all candidates"}
    (ROOT / "docs/java-scope-j1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

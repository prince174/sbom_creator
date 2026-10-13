"""Score static model fields against build effective POM after prediction."""
import json
import xml.etree.ElementTree as ET

from java_local_management import project
from java_local_parent import NS
from paired_express import sha
from paired_gson import OUT, WORK
from run import ROOT


def main():
    blobs = {p: (WORK / "src" / p).read_bytes() for p in ("pom.xml", "gson/pom.xml")}
    prediction = project(blobs, "gson/pom.xml")
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    for path, name in (("pom.xml", "parent-pom.xml"), ("gson/pom.xml", "pom.xml")):
        if sha(WORK / "src" / path) != receipt["reference_hashes"][name]:
            raise ValueError("Source changed")
    oracle_path = OUT / "effective-pom.xml"
    if sha(oracle_path) != receipt["reference_hashes"]["effective-pom.xml"]:
        raise ValueError("Reference changed")
    root = ET.fromstring(oracle_path.read_bytes())
    expected = sorted(tuple(d.findtext("m:" + k, namespaces=NS) for k in ("groupId", "artifactId", "version")) +
                      (d.findtext("m:scope", "compile", NS),)
                      for d in root.findall("m:dependencies/m:dependency", NS))
    actual = sorted(tuple(r["coordinate"]) + (r["scope"],) for r in prediction["rows"])
    report = {"experiment": "R28", "partition": "Gson development", "prediction": prediction,
              "reference_sha256": sha(oracle_path), "expected_fields": expected,
              "exact_model_field_match": expected == actual, "matched_rows": len(set(expected) & set(actual)),
              "reference_rows": len(expected), "predicted_rows": len(actual),
              "direct_precision": None, "direct_recall": None, "runtime_changed": False,
              "limitation": "One development build profile; model field comparison, not direct-edge accuracy"}
    (ROOT / "docs/java-local-management-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

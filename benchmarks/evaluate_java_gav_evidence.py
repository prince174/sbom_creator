"""Development Gson evidence only; source declarations precede oracle access."""
import json
import xml.etree.ElementTree as ET

from audit_maven_declarations import declarations
from java_gav_evidence import match
from java_local_parent import NS, chain
from paired_express import sha
from paired_gson import OUT, WORK
from run import ROOT


def main():
    blobs = {p: (WORK / "src" / p).read_bytes() for p in ("pom.xml", "gson/pom.xml")}
    local = chain(blobs, "gson/pom.xml")
    if local["status"] != "LOCAL_CHAIN_FOUND":
        raise ValueError("Local chain unavailable")
    parent, child = [ET.fromstring(blobs[p]) for p in ("pom.xml", "gson/pom.xml")]
    owner = tuple(child.findtext("m:" + k, namespaces=NS) or
                  (parent.findtext("m:" + k, namespaces=NS) if k != "artifactId" else None)
                  for k in ("groupId", "artifactId", "version"))
    source = json.loads((WORK / "analysis/source.syft.json").read_bytes())
    image = json.loads((WORK / "analysis/image.syft.json").read_bytes())
    predictions = []
    for dep in declarations(blobs["gson/pom.xml"])["dependencies"]:
        coordinate = tuple(dep[k] for k in ("groupId", "artifactId", "version"))
        if all(coordinate) and not dep["property_expression"]:
            result = match(source, image, owner, coordinate, "gson/pom.xml")
        else:
            result = {"status": "UNKNOWN", "reason": "nonliteral_declaration", "direct_edge_proven": False}
        predictions.append({"declared_gav": coordinate, "raw_scope": dep["scope"], "evidence": result})
    # Check immutable provenance only after computing candidates. No reference graph is read.
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    for name in ("source.syft.json", "image.syft.json"):
        if sha(WORK / "analysis" / name) != receipt["outputs"][name]:
            raise ValueError("Catalog changed")
    for path, name in (("pom.xml", "parent-pom.xml"), ("gson/pom.xml", "pom.xml")):
        if sha(WORK / "src" / path) != receipt["reference_hashes"][name]:
            raise ValueError("Source changed")
    report = {"experiment": "R27", "project": "java-gson", "partition": "development",
              "receipt_sha256": sha(OUT / "receipt.json"), "owner_gav": owner, "predictions": predictions,
              "runtime_changed": False, "reference_graph_used": False, "holdout_read": False,
              "direct_precision": None, "direct_recall": None, "version_accuracy": None,
              "reason": "Identity corroboration only; effective scope and complete inherited declarations unresolved"}
    (ROOT / "docs/java-gav-evidence-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

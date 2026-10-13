"""Inspect saved development evidence; no classifier and no oracle input leakage."""
import hashlib
import io
import json
import tarfile
import zipfile
from collections import Counter

from paired_commons_text import OUT, WORK
from paired_express import sha
from run import ROOT


def main():
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    for name in ("source.syft.json", "image.syft.json"):
        if sha(WORK / "analysis" / name) != receipt["outputs"][name]:
            raise ValueError("Input changed")
    if sha(WORK / "src/pom.xml") != receipt["reference_hashes"]["pom.xml"]:
        raise ValueError("POM changed")
    source = json.loads((WORK / "analysis/source.syft.json").read_bytes())
    image = json.loads((WORK / "analysis/image.syft.json").read_bytes())
    by_id = {a["id"]: a for a in source["artifacts"]}
    relationships = []
    for edge in source.get("artifactRelationships", []):
        if edge["type"] != "dependency-of":
            continue
        dependency, owner = by_id[edge["parent"]], by_id[edge["child"]]
        props = dependency.get("metadata", {}).get("pomProperties", {})
        relationships.append({"owner_name": owner["name"], "owner_id": owner["id"],
                              "dependency_name": dependency["name"], "dependency_group": props.get("groupId"),
                              "observed_source_version": dependency["version"], "raw_scope": props.get("scope"),
                              "effective_scope": None, "status": "not_classified"})
    source_pom = (WORK / "src/pom.xml").read_bytes()
    embedded = []
    with tarfile.open(WORK / "runtime-app.tar") as archive:
        for member in archive:
            if member.isfile() and member.name.endswith(".jar"):
                with zipfile.ZipFile(io.BytesIO(archive.extractfile(member).read())) as jar:
                    for name in jar.namelist():
                        if name.startswith("META-INF/maven/") and name.endswith("/pom.xml"):
                            raw = jar.read(name)
                            embedded.append({"jar": member.name, "path": name,
                                             "sha256": hashlib.sha256(raw).hexdigest(),
                                             "identical_to_source_pom": raw == source_pom})
    schema = json.loads((ROOT / "src/sbom_creator/schemas/syft-16.1.10.json").read_bytes())
    report = {"experiment": "R22", "runtime_changed": False, "partition": "Commons Text development",
              "receipt_sha256": sha(OUT / "receipt.json"), "source_relationships": relationships,
              "source_relationship_scopes": dict(Counter(r["raw_scope"] or "unspecified" for r in relationships)),
              "image_dependency_relationships": sum(e["type"] == "dependency-of" for e in image.get("artifactRelationships", [])),
              "image_pom_fields": {a["name"]: sorted(a.get("metadata", {}).get("pomProject", {})) for a in image["artifacts"]},
              "schema_pom_fields": sorted(schema["$defs"]["JavaPomProject"]["properties"]),
              "embedded_poms": embedded, "direct_precision": None, "direct_recall": None,
              "effective_pom_or_cyclonedx_used_as_prediction_input": False, "holdout_read": False,
              "next_hypothesis": "Source graph plus raw POM owner/scope and unique image GAV; unresolved inherited/profile scope stays UNKNOWN"}
    (ROOT / "docs/java-syft-evidence-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"source_scopes": report["source_relationship_scopes"], "image_edges": report["image_dependency_relationships"],
                      "embedded_source_match_count": sum(e["identical_to_source_pom"] for e in embedded)}))


if __name__ == "__main__":
    main()

"""Development POM structure audit, not a Maven resolver or direct classifier."""
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET

from paired_express import root_dependencies
from run import ROOT


def declarations(raw):
    if len(raw) > 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsupported XML input")
    root = ET.fromstring(raw)
    if root.tag != "{http://maven.apache.org/POM/4.0.0}project":
        raise ValueError("Unsupported POM namespace")
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    def value(node, key):
        item = node.find("m:" + key, ns)
        return item.text.strip() if item is not None and item.text else None
    rows = []
    for dep in root.findall("m:dependencies/m:dependency", ns):
        row = {key: value(dep, key) for key in ("groupId", "artifactId", "version", "scope", "optional", "type", "classifier")}
        row["property_expression"] = any("${" in (v or "") for v in row.values())
        row["exclusions"] = len(dep.findall("m:exclusions/m:exclusion", ns))
        row["effective_scope"] = None
        row["resolved_version"] = None
        rows.append(row)
    return {"status": "raw-root-declarations-only", "dependencies": rows,
            "parent_present": root.find("m:parent", ns) is not None,
            "management_entries": len(root.findall("m:dependencyManagement/m:dependencies/m:dependency", ns)),
            "profile_count": len(root.findall("m:profiles/m:profile", ns)),
            "profile_dependency_count": len(root.findall("m:profiles/m:profile/m:dependencies/m:dependency", ns)),
            "plugin_dependency_count": len(root.findall(".//m:plugin/m:dependencies/m:dependency", ns)),
            "modules": [m.text.strip() for m in root.findall("m:modules/m:module", ns) if m.text],
            "effective_model_complete": False}


def main():
    split = json.loads((ROOT / "benchmarks/direct-evaluation-split-v1.json").read_bytes())
    index = json.loads((ROOT / "benchmarks/references/build-v1/index.json").read_bytes())
    rows = []
    for item in index["projects"]:
        if item["language"] != "Java" or item["id"] not in split["development"]:
            continue
        repo = ROOT / "benchmarks/.work" / item["id"] / "src"
        raw = subprocess.check_output(["git", "show", item["commit"] + ":pom.xml"], cwd=repo)
        declaration = declarations(raw)
        reference_path = ROOT / item["sbom"]
        reference_raw = reference_path.read_bytes()
        bom = json.loads(reference_raw)
        by_ref = {c["bom-ref"]: c for c in bom.get("components", [])}
        reference = [by_ref[r] for r in root_dependencies(bom)]
        rows.append({"project": item["id"], "commit": item["commit"],
                     "pom_sha256": hashlib.sha256(raw).hexdigest(), "declaration": declaration,
                     "reference_sha256": hashlib.sha256(reference_raw).hexdigest(),
                     "reference_root": bom["metadata"]["component"].get("name"),
                     "reference_direct": [{k: c.get(k) for k in ("group", "name", "version", "purl")} for c in reference],
                     "image_pair_verified": False, "coordinate_comparison_scored": False})
    report = {"experiment": "R20", "partition": "development only", "runtime_changed": False,
              "holdout_read": False, "precision": None, "recall": None, "version_accuracy": None,
              "rows": rows}
    (ROOT / "docs/maven-declarations-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps([{ "project": r["project"], "root_declarations": len(r["declaration"]["dependencies"]),
                       "reference_root_edges": len(r["reference_direct"]),
                       "parent": r["declaration"]["parent_present"], "modules": r["declaration"]["modules"],
                       "profiles": r["declaration"]["profile_count"]} for r in rows]))


if __name__ == "__main__":
    main()

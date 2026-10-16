"""Publish corroborated Python package edges without changing inventory."""
from packageurl import PackageURL

from .python_projection import classify


def annotate(document, image, manifest):
    report = {k: v for k, v in manifest.items() if k != "document"}
    report.update(profile="python-root-runtime-P1", graph_complete=False, build_usage_proven=False, edges=[])
    if manifest.get("status") != "available":
        return report
    report.update(classify(manifest["document"], image))
    by_id = {}
    for component in document.get("components", []):
        ref = component["bom-ref"]
        aid = PackageURL.from_string(ref).qualifiers.get("package-id") if ref.startswith("pkg:") else ref
        by_id.setdefault(aid, []).append(component)
    for edge in report["edges"]:
        if edge["status"] != "DIRECT":
            continue
        owners = by_id.get(edge["owner_artifact_id"], [])
        targets = by_id.get(edge["artifact_id"], [])
        if len(owners) != 1 or len(targets) != 1:
            edge.update(status="UNKNOWN", reason="selected_inventory_identity_unavailable")
            continue
        owner, target = owners[0], targets[0]
        edge.update(owner_ref=owner["bom-ref"], component_ref=target["bom-ref"])
        target.setdefault("properties", []).extend([
            {"name": "sbom-creator:direct-owner", "value": owner["bom-ref"]},
            {"name": "sbom-creator:direct-scope", "value": "runtime-declaration"},
        ])
        graph = document.setdefault("dependencies", [])
        node = next((d for d in graph if d["ref"] == owner["bom-ref"]), None)
        if node is None:
            node = {"ref": owner["bom-ref"], "dependsOn": []}
            graph.append(node)
        node["dependsOn"] = sorted(set(node.get("dependsOn", [])) | {target["bom-ref"]})
    report["direct_count"] = sum(e["status"] == "DIRECT" for e in report["edges"])
    report["unknown_count"] = (None if report["status"] == "UNKNOWN" else
                               sum(e["status"] == "UNKNOWN" for e in report["edges"]))
    return report


def combine(npm, python):
    if python["status"] == "not-applicable":
        return npm
    if npm.get("status") == "not-applicable":
        return python
    edges = npm.get("edges", []) + python.get("edges", [])
    return {"profile": "combined-source-dependencies", "status": "partial", "graph_complete": False,
            "build_usage_proven": False, "edges": edges,
            "direct_count": sum(e["status"] == "DIRECT" for e in edges),
            "unknown_count": (None if any(r.get("status") == "UNKNOWN" for r in (npm, python)) else
                              sum(e["status"] == "UNKNOWN" for e in edges)),
            "profiles": [{k: v for k, v in r.items() if k != "edges"} for r in (npm, python)]}

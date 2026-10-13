"""Restricted literal management projection; no build-profile inference."""
import xml.etree.ElementTree as ET

from audit_maven_declarations import declarations
from java_local_parent import NS, chain
from java_profile_impact import audit

FIELDS = ("groupId", "artifactId", "version", "scope", "type", "classifier", "optional")


def project(blobs, module):
    local = chain(blobs, module)
    if local["status"] != "LOCAL_CHAIN_FOUND":
        return {"status": "UNKNOWN", "reason": local["reason"], "rows": []}
    paths = list(reversed(local["chain"]))
    roots = [ET.fromstring(blobs[p]) for p in paths]
    for root in roots[:-1]:
        if root.find("m:dependencies", NS) is not None:
            return {"status": "UNKNOWN", "reason": "inherited_declarations_unsupported", "rows": []}
    impact = audit([blobs[p] for p in paths])
    if any(p["declaration_impact"] == "POTENTIAL" for p in impact["profiles"]):
        return {"status": "UNKNOWN", "reason": "profile_declaration_impact", "rows": []}
    managed = {}
    for path, root in zip(paths, roots, strict=True):
        seen = set()
        for dep in root.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
            values = {k: dep.findtext("m:" + k, namespaces=NS) for k in FIELDS}
            if any("${" in (v or "") for v in values.values()):
                return {"status": "UNKNOWN", "reason": "managed_expression", "rows": []}
            if values["scope"] == "import" or values["type"] not in (None, "jar") or values["classifier"]:
                return {"status": "UNKNOWN", "reason": "unsupported_managed_type", "rows": []}
            key = (values["groupId"], values["artifactId"])
            if not all(key) or key in seen:
                return {"status": "UNKNOWN", "reason": "ambiguous_management", "rows": []}
            seen.add(key)
            # Field-level merge: nearer management overrides only supplied fields.
            merged = dict(managed.get(key, ({}, None))[0])
            merged.update({k: v for k, v in values.items() if v is not None})
            managed[key] = (merged, path)
    rows = []
    seen = set()
    for dep in declarations(blobs[module])["dependencies"]:
        key = (dep["groupId"], dep["artifactId"])
        if not all(key) or key in seen or dep["property_expression"]:
            return {"status": "UNKNOWN", "reason": "ambiguous_declaration", "rows": []}
        seen.add(key)
        if dep["type"] not in (None, "jar") or dep["classifier"]:
            return {"status": "UNKNOWN", "reason": "unsupported_dependency_type", "rows": []}
        management, origin = managed.get(key, ({}, None))
        resolved = {k: dep[k] if dep[k] is not None else management.get(k) for k in FIELDS}
        resolved["scope"] = resolved["scope"] or "compile"
        if not resolved["version"] or resolved["scope"] not in ("compile", "runtime", "test", "provided"):
            return {"status": "UNKNOWN", "reason": "unresolved_version_or_scope", "rows": []}
        rows.append({"coordinate": [*key, resolved["version"]], "scope": resolved["scope"],
                     "owner_module": module, "management_pom": origin,
                     "status": "STATIC_MODEL_CANDIDATE", "direct_edge_proven": False})
    return {"status": "STATIC_MODEL_CANDIDATES", "rows": rows, "effective_model_proven": False,
            "limitation": "No settings/CLI/extensions/plugin effects; inherited declarations unsupported"}

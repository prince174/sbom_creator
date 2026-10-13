"""Static profile impact audit, not activation or effective-model resolution."""
import re
import xml.etree.ElementTree as ET

from audit_maven_declarations import declarations
from java_local_parent import NS


def audit(raw_poms):
    roots = []
    for raw in raw_poms:
        declarations(raw)
        roots.append(ET.fromstring(raw))
    properties = {}
    relevant = set()
    profiles = []
    for root in roots:
        for node in root.findall(".//m:properties", NS):
            for prop in node:
                name = prop.tag.split("}")[-1]
                properties.setdefault(name, set()).update(re.findall(r"\$\{([^}]+)\}", prop.text or ""))
        for container in [root, *root.findall("m:profiles/m:profile", NS)]:
            for path in ("m:dependencies", "m:dependencyManagement"):
                node = container.find(path, NS)
                if node is not None:
                    relevant.update(re.findall(r"\$\{([^}]+)\}", ET.tostring(node, encoding="unicode")))
        profiles.extend(root.findall("m:profiles/m:profile", NS))
    while True:
        expanded = relevant | {value for key in relevant for value in properties.get(key, ())}
        if expanded == relevant:
            break
        relevant = expanded
    result = []
    for profile in profiles:
        props = profile.find("m:properties", NS)
        changed = {p.tag.split("}")[-1] for p in props} if props is not None else set()
        dependencies = profile.find("m:dependencies", NS) is not None
        management = profile.find("m:dependencyManagement", NS) is not None
        result.append({"id": profile.findtext("m:id", "", NS),
                       "dependency_section": dependencies, "management_section": management,
                       "properties_affecting_declarations": sorted(changed & relevant),
                       "build_section": profile.find("m:build", NS) is not None,
                       "activation": "UNKNOWN",
                       "declaration_impact": "POTENTIAL" if dependencies or management or changed & relevant else "NO_STATIC_REFERENCE_FOUND"})
    return {"profiles": result, "referenced_properties": sorted(relevant),
            "effective_model_resolved": False, "direct_edges": [],
            "limitation": "No settings/CLI/extensions/plugin effects; absence of a static reference is not proof of build invariance"}

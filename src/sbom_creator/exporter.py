"""Retain only positively selected package components in Syft's CycloneDX export."""
import copy

from packageurl import PackageURL

from .validation import schema


def packages_only(cyclonedx, selected_syft):
    document = copy.deepcopy(cyclonedx)
    accepted = {a["id"] for a in selected_syft["artifacts"]}
    retained = []
    seen = set()
    omitted = 0
    for component in document.get("components", []):
        reference = component.get("bom-ref", "")
        artifact_id = reference if reference in accepted else None
        if reference.startswith("pkg:"):
            artifact_id = PackageURL.from_string(reference).qualifiers.get("package-id")
        if artifact_id in accepted:
            if artifact_id in seen:
                raise ValueError("Converter emitted duplicate selected package")
            seen.add(artifact_id)
            retained.append(component)
        elif component.get("type") in {"file", "operating-system"}:
            omitted += 1
        else:
            raise ValueError("Converter emitted a component without an accepted package identity")
    if seen != accepted:
        raise ValueError("Converter lost one or more accepted package identities")
    document["components"] = retained
    # Syft's newer SPDX list can contain IDs absent from the pinned CDX1.6 schema.
    # Keep their exact label as a named license, never silently drop license evidence.
    spdx_ids = set(schema("spdx.schema.json")["enum"])
    for component in retained + [document.get("metadata", {}).get("component", {})]:
        for entry in component.get("licenses", []):
            license_data = entry.get("license", {})
            identifier = license_data.get("id")
            if identifier and identifier not in spdx_ids:
                license_data.pop("id")
                license_data["name"] = identifier
                component.setdefault("properties", []).append({
                    "name": "sbom-creator:original-license-id", "value": identifier,
                })
    valid = {c["bom-ref"] for c in retained}
    subject = document.get("metadata", {}).get("component", {}).get("bom-ref")
    if subject:
        valid.add(subject)
    dependencies = []
    for dependency in document.get("dependencies", []):
        if dependency["ref"] not in valid:
            continue
        for field in ("dependsOn", "provides"):
            if field in dependency:
                dependency[field] = [ref for ref in dependency[field] if ref in valid]
        dependencies.append(dependency)
    document["dependencies"] = dependencies
    document.setdefault("metadata", {}).setdefault("properties", []).append({
        "name": "sbom-creator:auxiliary-components-omitted", "value": str(omitted),
    })
    return document

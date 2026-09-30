"""Retain only positively selected package components in Syft's CycloneDX export."""
import copy
import hashlib
import json
import uuid

from packageurl import PackageURL

from .validation import schema, validate_cyclonedx, validate_export_identity

OS_PACKAGE_TYPES = frozenset({"apk", "deb", "rpm", "alpm", "portage", "nix", "opkg"})


def is_os_package(artifact):
    """System-package inventory, never a guess based on a library's name."""
    if artifact.get("type") in OS_PACKAGE_TYPES:
        return True
    try:
        return PackageURL.from_string(artifact.get("purl", "")).type in OS_PACKAGE_TYPES
    except (ValueError, TypeError):
        return False


def split_inventory(full, selected_syft):
    """Partition accepted packages without changing presence decisions or raw evidence."""
    validate_cyclonedx(full)
    validate_export_identity(full, selected_syft)
    os_ids = {a["id"] for a in selected_syft["artifacts"] if is_os_package(a)}
    all_ids = {a["id"] for a in selected_syft["artifacts"]}
    identity = full.get("serialNumber") or hashlib.sha256(json.dumps(full, sort_keys=True).encode()).hexdigest()
    documents = {}
    for scope, ids in (("non-os-packages", all_ids - os_ids), ("os-packages", os_ids)):
        document = copy.deepcopy(full)
        document["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, identity + ":" + scope))
        def selected(component, accepted_ids=ids):
            reference = component["bom-ref"]
            aid = PackageURL.from_string(reference).qualifiers.get("package-id") if reference.startswith("pkg:") else reference
            return aid in accepted_ids
        document["components"] = [c for c in document.get("components", []) if selected(c)]
        valid = {c["bom-ref"] for c in document["components"]}
        subject = document.get("metadata", {}).get("component", {}).get("bom-ref")
        if subject:
            valid.add(subject)
        dependencies = []
        for edge in document.get("dependencies", []):
            if edge["ref"] not in valid:
                continue
            for key in ("dependsOn", "provides"):
                if key in edge:
                    edge[key] = [ref for ref in edge[key] if ref in valid]
            dependencies.append(edge)
        document["dependencies"] = dependencies
        properties = document.setdefault("metadata", {}).setdefault("properties", [])
        properties.extend([
            {"name": "sbom-creator:inventory-scope", "value": scope},
            {"name": "sbom-creator:project-build-usage", "value": "not-established"},
            {"name": "sbom-creator:cross-scope-relationships", "value": "See full.cdx.json; filtered in this view"},
        ])
        validate_cyclonedx(document)
        validate_export_identity(document, {"artifacts": [a for a in selected_syft["artifacts"] if a["id"] in ids]})
        documents[scope] = document
    return documents["non-os-packages"], documents["os-packages"]


def validate_inventory_views(full, application, os_packages, selected_syft):
    for document, os_scope in ((application, False), (os_packages, True)):
        validate_cyclonedx(document)
        validate_export_identity(document, {"artifacts": [a for a in selected_syft["artifacts"]
                                                           if is_os_package(a) == os_scope]})
    expected_application, expected_os = split_inventory(full, selected_syft)
    if application != expected_application or os_packages != expected_os:
        raise ValueError("Inventory views differ from the verified full inventory partition")


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

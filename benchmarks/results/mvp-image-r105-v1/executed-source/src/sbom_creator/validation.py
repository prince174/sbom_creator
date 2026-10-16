"""Offline validation against bundled official schemas and reference integrity."""
import json
import re
from collections import Counter
from importlib.resources import files

from jsonschema import Draft7Validator, Draft202012Validator
from packageurl import PackageURL
from referencing import Registry, Resource


def schema(name):
    return json.loads(files("sbom_creator").joinpath("schemas", name).read_text("utf-8"))


def validate_syft(document):
    if document.get("schema", {}).get("version") != "16.1.10":
        raise ValueError("Expected Syft schema 16.1.10 from Syft 1.51.1")
    Draft202012Validator(schema("syft-16.1.10.json")).validate(document)
    ids = [a["id"] for a in document["artifacts"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate Syft artifact ID")
    valid = set(ids) | {f["id"] for f in document.get("files", [])}
    source_id = document.get("source", {}).get("id")
    if source_id:
        valid.add(source_id)
    for relation in document.get("artifactRelationships", []):
        if relation["parent"] not in valid or relation["child"] not in valid:
            raise ValueError("Dangling Syft relationship")


def validate_cyclonedx(document):
    if document.get("specVersion") != "1.6":
        raise ValueError("Expected CycloneDX 1.6")
    registry = Registry()
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        data = schema(name)
        resource = Resource.from_contents(data)
        registry = registry.with_resource(f"http://cyclonedx.org/schema/{name}", resource)
        registry = registry.with_resource(f"https://cyclonedx.org/schema/{name}", resource)
        registry = registry.with_resource(name, resource)
    Draft7Validator(schema("bom-1.6.schema.json"), registry=registry).validate(document)
    refs = []

    def collect(items):
        for item in items:
            if "bom-ref" in item:
                refs.append(item["bom-ref"])
            collect(item.get("components", []))

    collect(document.get("components", []))
    collect([document.get("metadata", {}).get("component", {})])
    if len(refs) != len(set(refs)):
        raise ValueError("Duplicate CycloneDX bom-ref")
    valid = set(refs)
    dependency_refs = set()
    for dependency in document.get("dependencies", []):
        if dependency["ref"] in dependency_refs:
            raise ValueError("Duplicate CycloneDX dependency entry")
        dependency_refs.add(dependency["ref"])
        if dependency["ref"] not in valid:
            raise ValueError("Unknown CycloneDX dependency ref")
        if any(ref not in valid for ref in dependency.get("dependsOn", []) + dependency.get("provides", [])):
            raise ValueError("Dangling CycloneDX dependency")


def _normalized_purl(value):
    parsed = PackageURL.from_string(value)
    if parsed.type == "pypi":
        parsed = parsed._replace(name=re.sub(r"[-_.]+", "-", parsed.name).lower())
    return parsed


def validate_export_identity(document, selected_syft):
    """Check that each exported package preserves its selected identity exactly.

    package-id only locates the original record; it does not authorize a changed
    name, namespace, version, PURL qualifier or subpath. Files and the image subject
    are outside the selected package inventory.
    """
    artifacts = selected_syft["artifacts"]
    expected = {artifact["id"]: artifact for artifact in artifacts}
    if len(expected) != len(artifacts):
        raise ValueError("Duplicate selected Syft artifact ID")
    seen = []
    components = document.get("components", [])
    if document.get("metadata", {}).get("component", {}).get("components"):
        raise ValueError("Unexpected nested subject components in flat package export")
    for component in components:
        if component.get("components"):
            raise ValueError("Unexpected nested components in flat package export")
        reference = component.get("bom-ref", "")
        artifact_id = (_normalized_purl(reference).qualifiers.get("package-id")
                       if reference.startswith("pkg:") else reference)
        if artifact_id not in expected:
            raise ValueError("Exported package does not identify a selected Syft artifact")
        artifact = expected[artifact_id]
        seen.append(artifact_id)
        if (component.get("version") or "") != (artifact.get("version") or ""):
            raise ValueError("Exported package version differs from selected Syft identity")
        original_purl, exported_purl = artifact.get("purl"), component.get("purl")
        if bool(original_purl) != bool(exported_purl):
            raise ValueError("Exported package lost or invented its PURL")
        allowed_names = {(artifact.get("name"), "")}
        if original_purl:
            parsed = _normalized_purl(original_purl)
            if parsed.to_string() != _normalized_purl(exported_purl).to_string():
                raise ValueError("Exported package PURL differs from selected Syft identity")
            if parsed.namespace:
                # Syft can retain a full module/scoped name or split it into the
                # CycloneDX name/group fields. The exact PURL remains mandatory.
                allowed_names.add((parsed.name, parsed.namespace))
                allowed_names.add((artifact.get("name"), parsed.namespace))
        if (component.get("name"), component.get("group") or "") not in allowed_names:
            raise ValueError("Exported package name/group differs from selected Syft identity")
    if Counter(seen) != Counter(expected.keys()):
        raise ValueError("Exported packages do not map one-to-one to selected Syft identities")

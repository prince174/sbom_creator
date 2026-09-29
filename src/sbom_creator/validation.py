"""Offline validation against bundled official schemas and reference integrity."""
import json
from importlib.resources import files

from jsonschema import Draft7Validator, Draft202012Validator
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

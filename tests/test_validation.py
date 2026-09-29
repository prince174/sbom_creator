
import pytest
from jsonschema import ValidationError

from sbom_creator.validation import validate_cyclonedx, validate_export_identity, validate_syft


def cdx():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": "a", "bom-ref": "a"}],
            "dependencies": [{"ref": "a", "dependsOn": []}]}


def test_cyclonedx_offline_license_reference():
    data = cdx()
    data["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
    validate_cyclonedx(data)


@pytest.mark.parametrize("kind", ["duplicate", "dangling", "invalid_schema", "wrong_version"])
def test_invalid_cyclonedx_is_rejected(kind):
    data = cdx()
    if kind == "duplicate":
        data["components"].append(dict(data["components"][0]))
    elif kind == "dangling":
        data["dependencies"][0]["dependsOn"] = ["missing"]
    elif kind == "invalid_schema":
        data["components"][0]["type"] = "invented-type"
    else:
        data["specVersion"] = "1.5"
    with pytest.raises((ValueError, ValidationError)):
        validate_cyclonedx(data)


def test_syft_wrong_schema_rejected():
    with pytest.raises(ValueError, match="16.1.10"):
        validate_syft({"schema": {"version": "16.1.0"}, "artifacts": []})


def test_provides_reference_integrity_uses_component_ids():
    data = cdx()
    data["components"].append({"type": "library", "name": "provided", "bom-ref": "provided"})
    data["dependencies"][0]["provides"] = ["provided"]
    validate_cyclonedx(data)
    data["dependencies"][0]["provides"] = ["absent"]
    with pytest.raises(ValueError, match="Dangling CycloneDX"):
        validate_cyclonedx(data)


@pytest.mark.parametrize("artifact_name,name,group,purl", [
    ("library", "library", "org.example", "pkg:maven/org.example/library@1.2.3?type=jar"),
    ("@scope/library", "library", "@scope", "pkg:npm/%40scope/library@1.2.3"),
    ("@scope/library", "@scope/library", "", "pkg:npm/%40scope/library@1.2.3"),
    ("github.com/example/library", "library", "github.com/example", "pkg:golang/github.com/example/library@1.2.3"),
    ("Simple Launcher", "Simple Launcher", "", ""),
])
def test_export_identity_accepts_exact_names_or_namespace_group_split(artifact_name, name, group, purl):
    artifact = {"id": "package1", "name": artifact_name, "version": "1.2.3", "purl": purl}
    component = {"bom-ref": "package1", "name": name, "version": "1.2.3"}
    if group:
        component["group"] = group
    if purl:
        component["purl"] = purl
    validate_export_identity({"components": [component]}, {"artifacts": [artifact]})


@pytest.mark.parametrize("changed", [
    {"name": "different"}, {"version": "9.9.9"},
    {"purl": "pkg:npm/%40scope/library@1.2.3?arch=arm64"},
    {"purl": "pkg:npm/%40other/library@1.2.3?arch=amd64"},
    {"group": "wrong-namespace"}, {"purl": None},
])
def test_export_identity_rejects_changed_identity_even_with_correct_package_id(changed):
    artifact = {"id": "package1", "name": "@scope/library", "version": "1.2.3",
                "purl": "pkg:npm/%40scope/library@1.2.3?arch=amd64"}
    component = {"bom-ref": "pkg:npm/%40scope/library@1.2.3?arch=amd64&package-id=package1",
                 "name": "library", "group": "@scope", "version": "1.2.3", "purl": artifact["purl"], **changed}
    with pytest.raises(ValueError, match="Exported package"):
        validate_export_identity({"components": [component]}, {"artifacts": [artifact]})

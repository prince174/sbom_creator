
import pytest
from jsonschema import ValidationError

from sbom_creator.validation import validate_cyclonedx, validate_syft


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

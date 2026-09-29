import pytest

from sbom_creator.exporter import packages_only
from sbom_creator.validation import validate_cyclonedx


def example():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [
            {"type": "library", "name": "a", "bom-ref": "pkg:npm/a@1?package-id=abc"},
            {"type": "file", "name": "/a", "bom-ref": "file1"},
            {"type": "operating-system", "name": "alpine", "bom-ref": "os1"}],
        "dependencies": [
            {"ref": "pkg:npm/a@1?package-id=abc", "dependsOn": ["file1"]},
            {"ref": "os1", "dependsOn": ["pkg:npm/a@1?package-id=abc"]}]}


def test_package_export_does_not_count_file_evidence_as_dependency():
    result = packages_only(example(), {"artifacts": [{"id": "abc"}]})
    assert len(result["components"]) == 1
    assert result["dependencies"] == [{"ref": "pkg:npm/a@1?package-id=abc", "dependsOn": []}]
    validate_cyclonedx(result)


def test_converter_cannot_silently_lose_accepted_package():
    with pytest.raises(ValueError, match="lost"):
        packages_only(example(), {"artifacts": [{"id": "abc"}, {"id": "missing"}]})


def test_converter_cannot_add_unselected_package():
    document = example()
    document["components"].append({"type": "library", "name": "injected", "bom-ref": "bad"})
    with pytest.raises(ValueError, match="without an accepted"):
        packages_only(document, {"artifacts": [{"id": "abc"}]})


def test_newer_spdx_id_preserved_as_named_license_for_pinned_schema():
    document = example()
    document["components"][0]["licenses"] = [{"license": {"id": "Artistic-dist"}}]
    result = packages_only(document, {"artifacts": [{"id": "abc"}]})
    assert result["components"][0]["licenses"] == [{"license": {"name": "Artistic-dist"}}]
    validate_cyclonedx(result)

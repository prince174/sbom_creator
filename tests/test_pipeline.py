"""Real pinned-Syft roundtrip, plus atomic publication and failure boundaries.

These generated scanner fixtures test reconciliation/conversion, not a real
Bitbucket checkout or proof that a production build installed these packages.
"""

import copy
import json
import os
import shutil
from pathlib import Path

import pytest

from sbom_creator.acquire import Settings
from sbom_creator.core import rules_assessor
from sbom_creator.exporter import packages_only
from sbom_creator.pipeline import ARTIFACTS, AnalysisError, analyze, analyze_local, publish_catalogs
from sbom_creator.scanner import convert, scan_source
from sbom_creator.validation import validate_cyclonedx, validate_export_identity, validate_syft


@pytest.fixture(scope="module")
def real_catalogs(tmp_path_factory):
    executable = os.getenv("SBOM_SYFT_BINARY") or shutil.which("syft")
    local = Path(__file__).resolve().parents[1] / ".tools" / "syft" / "syft.exe"
    if not executable and local.is_file():
        executable = str(local)
    if not executable:
        pytest.skip("Pinned Syft executable is required for scanner/converter integration")
    root = tmp_path_factory.mktemp("real-syft-fixtures")
    source = root / "source"
    image = root / "image-root-fixture"
    source.mkdir()
    image.mkdir()
    (source / "requirements.txt").write_text("kept-package==1.2.3\nsource-only==4.5.6\n", encoding="utf-8")
    for name, version in (("kept-package", "1.2.3"), ("excluded-package", "7.8.9")):
        metadata = image / "usr" / "lib" / "python" / "site-packages" / f"{name}-{version}.dist-info"
        metadata.mkdir(parents=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nLicense: MIT\n", encoding="utf-8")
        (metadata / "RECORD").write_text("", encoding="utf-8")
    settings = Settings(syft_binary=str(Path(executable).resolve()))
    source_document = scan_source(source, root / "source.syft.json", settings)
    image_document = scan_source(image, root / "image.syft.json", settings)
    return source_document, image_document, settings


def _select_one(candidates):
    return [{"candidate_id": c["candidate_id"],
             "tp_score": 70 if "excluded-package" in (c["identity"] or "") else 99,
             "reason": "Independent test assessment exercises the strict policy threshold",
             "evidence_ids": [e["id"] for e in c["evidence"]], "missing_evidence": []}
            for c in candidates]


def test_actual_syft_conversion_has_no_excluded_component_or_dangling_ref(real_catalogs, tmp_path):
    source, image, settings = real_catalogs
    output = tmp_path / "published"
    summary = publish_catalogs(source, image, output, settings, _select_one,
                               {"mode": "test-assessor", "test_scope": "generated directory fixtures"})
    assert summary["decisions"] == {"INCLUDE": 1, "EXCLUDE": 1, "UNKNOWN": 1}
    assert summary["partial"] is True
    assert {path.name for path in output.iterdir()} == set(ARTIFACTS)
    selected = json.loads((output / "selected.syft.json").read_text("utf-8"))
    cdx = json.loads((output / "final.cdx.json").read_text("utf-8"))
    provenance = json.loads((output / "provenance.json").read_text("utf-8"))
    assert provenance["assessment"]["mode"] == "external-assessor"
    assert provenance["assessment"]["verified_model"] is False
    validate_syft(selected)
    validate_cyclonedx(cdx)
    assert [a["name"] for a in selected["artifacts"]] == ["kept-package"]
    assert [a["name"] for a in cdx["components"]] == ["kept-package"]
    component_refs = {a["bom-ref"] for a in cdx["components"]}
    subject_ref = cdx.get("metadata", {}).get("component", {}).get("bom-ref")
    valid_refs = component_refs | ({subject_ref} if subject_ref else set())
    for dependency in cdx.get("dependencies", []):
        assert dependency["ref"] in valid_refs
        assert set(dependency.get("dependsOn", [])) <= valid_refs
    assert not list(tmp_path.glob(".publish-*"))
    with pytest.raises(FileExistsError):
        publish_catalogs(source, image, output, settings, rules_assessor)


def test_actual_syft_conversion_preserves_scoped_qualified_and_no_purl_identities(real_catalogs, tmp_path):
    """Synthetic identities through the real pinned converter, not claimed build fixtures."""
    _, image, settings = real_catalogs
    selected = copy.deepcopy(image)
    selected["artifacts"] = [
        {"id": "scoped-npm", "name": "@scope/library", "version": "1.2.3", "type": "npm",
         "foundBy": "javascript-package-cataloger", "locations": [], "licenses": [], "language": "javascript",
         "cpes": [], "purl": "pkg:npm/%40scope/library@1.2.3"},
        {"id": "qualified-maven", "name": "library", "version": "1.2.3", "type": "java-archive",
         "foundBy": "java-archive-cataloger", "locations": [], "licenses": [], "language": "java",
         "cpes": [], "purl": "pkg:maven/org.example/library@1.2.3?type=jar"},
        {"id": "binary-no-purl", "name": "Simple Launcher", "version": "1.2.3", "type": "binary",
         "foundBy": "pe-cataloger", "locations": [], "licenses": [], "language": "", "cpes": [], "purl": ""},
    ]
    selected["artifactRelationships"] = []
    validate_syft(selected)
    path = tmp_path / "selected.syft.json"
    path.write_text(json.dumps(selected), encoding="utf-8")
    cdx = packages_only(convert(path, tmp_path / "converted.cdx.json", settings), selected)
    validate_cyclonedx(cdx)
    validate_export_identity(cdx, selected)
    assert len(cdx["components"]) == 3


@pytest.mark.parametrize("field,value", [("name", "invented-package"), ("version", "999.0")])
def test_publication_rejects_converter_identity_drift(real_catalogs, tmp_path, monkeypatch, field, value):
    source, image, settings = real_catalogs
    def drift(selected, final, config):
        cdx = convert(selected, final, config)
        cdx["components"][0][field] = value
        return cdx
    monkeypatch.setattr("sbom_creator.pipeline.convert", drift)
    output = tmp_path / "identity-drift"
    with pytest.raises(AnalysisError) as failure:
        publish_catalogs(source, image, output, settings, rules_assessor)
    assert failure.value.error_type == "ValueError"
    assert not output.exists()
    assert not list(tmp_path.glob(".publish-*"))
    assert not (tmp_path / "identity-drift.diagnostics" / "final.cdx.json").exists()


def test_rejected_assessment_or_schema_never_publishes_final(real_catalogs, tmp_path):
    source, image, settings = real_catalogs
    output = tmp_path / "rejected"
    with pytest.raises(AnalysisError) as failure:
        publish_catalogs(source, image, output, settings, lambda candidates: [])
    assert failure.value.error_type == "ValueError"
    assert not output.exists()
    diagnostics = tmp_path / "rejected.diagnostics"
    failure_info = json.loads((diagnostics / "failure.json").read_text("utf-8"))
    assert failure_info["final_published"] is False
    assert failure_info["stage"] == "reconcile_convert_validate"
    assert (diagnostics / "source.syft.json").is_file()
    assert (diagnostics / "image.syft.json").is_file()
    assert not (diagnostics / "final.cdx.json").exists()
    invalid = copy.deepcopy(image)
    invalid["artifacts"][0]["id"] = 77
    with pytest.raises(AnalysisError) as failure:
        publish_catalogs(source, invalid, output, settings, rules_assessor)
    assert failure.value.error_type == "ValidationError"
    assert not output.exists()


def test_conversion_failure_removes_staging_and_prevents_partial_publication(real_catalogs, tmp_path, monkeypatch):
    source, image, settings = real_catalogs
    output = tmp_path / "failed-conversion"
    def fail(selected, final, settings):
        final.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
        raise RuntimeError("Simulated converter failure")
    monkeypatch.setattr("sbom_creator.pipeline.convert", fail)
    with pytest.raises(AnalysisError) as failure:
        publish_catalogs(source, image, output, settings, rules_assessor)
    assert failure.value.error_type == "RuntimeError"
    assert not output.exists()
    assert not list(tmp_path.glob(".publish-*"))
    failure_text = (tmp_path / "failed-conversion.diagnostics" / "failure.json").read_text("utf-8")
    assert "Simulated converter failure" not in failure_text


@pytest.mark.parametrize("checkout_coverage", [
    {"gitmodules_present": True, "submodules_fetched": False, "lfs_pointer_paths": []},
    {"gitmodules_present": False, "lfs_fetched": False, "lfs_pointer_paths": ["lib/package.jar"]},
])
def test_unfetched_checkout_content_marks_partial_with_no_unknown_candidates(real_catalogs, tmp_path, checkout_coverage):
    _, image, settings = real_catalogs
    # Identical source/image inventories give no source-only UNKNOWN candidates.
    output = tmp_path / "incomplete-checkout"
    summary = publish_catalogs(image, image, output, settings, rules_assessor,
                               {"git": {"coverage": checkout_coverage}})
    assert summary["decisions"].get("UNKNOWN", 0) == 0
    assert summary["partial"] is True
    coverage = json.loads((output / "coverage.json").read_text("utf-8"))
    assert coverage["partial_inventory"] is True
    assert coverage["source_checkout_incomplete"] is True
    assert coverage["source_coverage"] == checkout_coverage
    # This cataloger ran without finding any package in the Python-only fixture.
    assert "java-pom-cataloger" in coverage["source_catalogers"]
    provenance = json.loads((output / "provenance.json").read_text("utf-8"))
    assert provenance["assessment"]["mode"] == "rules"


REMOTE_SETTINGS = Settings(bitbucket_hosts=("bitbucket.org",), registry_hosts=("registry.example",))
REPOSITORY_URL = "https://bitbucket.org/workspace/project.git"
COMMIT = "a" * 40
IMAGE_REFERENCE = "registry.example/project:1"


@pytest.mark.parametrize("remote", [False, True])
def test_image_scan_failure_preserves_source_before_workspace_cleanup(tmp_path, monkeypatch, remote):
    output = tmp_path / "failed-image"
    source_path = tmp_path / "checkout"
    source_path.mkdir()
    source_document = {"artifacts": [{"id": "completed-source-observation"}]}
    failed_workspaces = []

    def scan_completed_source(checkout_path, destination, settings):
        failed_workspaces.append(destination.parent)
        destination.write_text(json.dumps(source_document), encoding="utf-8")
        return source_document

    def image_failure(*args):
        raise RuntimeError("Bearer secret-from-registry-error")

    def checkout_completed(url, commit, destination, settings):
        destination.mkdir()
        return {"repository_url": url, "commit": commit, "coverage": {"submodules_fetched": False}}

    monkeypatch.setattr("sbom_creator.pipeline.scan_source", scan_completed_source)
    monkeypatch.setattr("sbom_creator.pipeline.scan_image", image_failure)
    monkeypatch.setattr("sbom_creator.pipeline.checkout", checkout_completed)
    with pytest.raises(AnalysisError) as failure:
        if remote:
            analyze(REPOSITORY_URL, COMMIT, IMAGE_REFERENCE, output, REMOTE_SETTINGS, mode="rules")
        else:
            analyze_local(source_path, IMAGE_REFERENCE, output, REMOTE_SETTINGS, mode="rules")
    assert failure.value.stage == "image_scan"
    assert failure.value.error_type == "RuntimeError"
    assert "secret-from-registry-error" not in str(failure.value)
    diagnostics = tmp_path / "failed-image.diagnostics"
    assert json.loads((diagnostics / "source.syft.json").read_text("utf-8")) == source_document
    details = json.loads((diagnostics / "failure.json").read_text("utf-8"))
    assert details == {"status": "failed", "stage": "image_scan", "error_type": "RuntimeError", "final_published": False}
    provenance = json.loads((diagnostics / "provenance.json").read_text("utf-8"))
    assert provenance["mode"] == "rules" and "git" in provenance
    if remote:
        assert provenance["git"]["commit"] == COMMIT
    assert not output.exists()
    assert not (diagnostics / "final.cdx.json").exists()
    assert not (diagnostics / "image.syft.json").exists()
    assert all(not path.exists() for path in failed_workspaces)
    assert all("secret-from-registry-error" not in path.read_text("utf-8") for path in diagnostics.iterdir())


@pytest.mark.parametrize("stage", ["configuration", "model_configuration", "checkout"])
def test_early_remote_failures_save_sanitized_stage_without_publishing(tmp_path, monkeypatch, stage):
    output = tmp_path / "early-failure"

    def fail(*args, **kwargs):
        raise ValueError("credential=do-not-record-this-secret")

    settings = REMOTE_SETTINGS
    if stage == "configuration":
        monkeypatch.setattr(Settings, "from_env", fail)
        settings = None
    elif stage == "model_configuration":
        monkeypatch.setattr("sbom_creator.pipeline.assessor_for", fail)
    else:
        monkeypatch.setattr("sbom_creator.pipeline.checkout", fail)
    with pytest.raises(AnalysisError) as failure:
        analyze(REPOSITORY_URL, COMMIT, IMAGE_REFERENCE, output, settings, mode="rules")
    assert failure.value.stage == stage and failure.value.error_type == "ValueError"
    diagnostics = tmp_path / "early-failure.diagnostics"
    assert json.loads((diagnostics / "failure.json").read_text("utf-8"))["stage"] == stage
    assert not output.exists()
    assert {path.name for path in diagnostics.iterdir()} == {"failure.json", "provenance.json"}
    assert all("do-not-record-this-secret" not in path.read_text("utf-8") for path in diagnostics.iterdir())


def test_invalid_url_credentials_are_not_copied_to_failure_provenance(tmp_path):
    output = tmp_path / "invalid-input"
    with pytest.raises(AnalysisError) as failure:
        analyze("https://user:input-secret@bitbucket.org/workspace/project.git", COMMIT,
                IMAGE_REFERENCE, output, REMOTE_SETTINGS, mode="rules")
    assert failure.value.stage == "input_validation"
    diagnostics = tmp_path / "invalid-input.diagnostics"
    assert all("input-secret" not in path.read_text("utf-8") for path in diagnostics.iterdir())
    assert not output.exists()


@pytest.mark.parametrize("remote", [False, True])
def test_existing_output_is_preserved_before_any_configuration_or_acquisition(tmp_path, monkeypatch, remote):
    output = tmp_path / "existing"
    output.mkdir()
    (output / "final.cdx.json").write_bytes(b"previous-verified-result")

    def forbidden(*args, **kwargs):
        raise AssertionError("Existing output must fail before starting work")

    monkeypatch.setattr(Settings, "from_env", forbidden)
    with pytest.raises(FileExistsError):
        if remote:
            analyze(REPOSITORY_URL, COMMIT, IMAGE_REFERENCE, output, mode="rules")
        else:
            analyze_local(tmp_path, IMAGE_REFERENCE, output, mode="rules")
    assert (output / "final.cdx.json").read_bytes() == b"previous-verified-result"
    assert not (tmp_path / "existing.diagnostics").exists()


def test_repeated_failure_preserves_first_attempt_without_stale_scans_in_second(tmp_path, monkeypatch):
    source_path = tmp_path / "checkout"
    source_path.mkdir()
    output = tmp_path / "retry"
    original_source = {"artifacts": [{"id": "first-attempt-source"}]}

    def first_source(checkout_path, destination, settings):
        destination.write_text(json.dumps(original_source), encoding="utf-8")
        return original_source

    def image_failure(*args):
        raise RuntimeError("First image request failed")

    monkeypatch.setattr("sbom_creator.pipeline.scan_source", first_source)
    monkeypatch.setattr("sbom_creator.pipeline.scan_image", image_failure)
    with pytest.raises(AnalysisError) as first:
        analyze_local(source_path, IMAGE_REFERENCE, output, REMOTE_SETTINGS, mode="rules")
    assert first.value.stage == "image_scan"
    first_diagnostics = tmp_path / "retry.diagnostics"
    original_files = {path.name: path.read_bytes() for path in first_diagnostics.iterdir()}

    def second_source(*args):
        raise OSError("Second source scan failed before producing output")

    monkeypatch.setattr("sbom_creator.pipeline.scan_source", second_source)
    with pytest.raises(AnalysisError) as second:
        analyze_local(source_path, IMAGE_REFERENCE, output, REMOTE_SETTINGS, mode="rules")
    assert second.value.stage == "source_scan"
    siblings = list(tmp_path.glob("retry.diagnostics-*"))
    assert len(siblings) == 1
    assert {path.name: path.read_bytes() for path in first_diagnostics.iterdir()} == original_files
    assert {path.name for path in siblings[0].iterdir()} == {"failure.json", "provenance.json"}
    assert json.loads((siblings[0] / "failure.json").read_text("utf-8"))["stage"] == "source_scan"
    assert not output.exists()

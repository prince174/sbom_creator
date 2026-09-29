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
from sbom_creator.pipeline import ARTIFACTS, AnalysisError, publish_catalogs
from sbom_creator.scanner import scan_source
from sbom_creator.validation import validate_cyclonedx, validate_syft


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

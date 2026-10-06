import copy
import importlib.util
import io
import json
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from sbom_creator.acquire import Settings
from sbom_creator.core import rules_assessor
from sbom_creator.llm import LlmConfig, OpenAICompatibleAssessor
from sbom_creator.pipeline import publish_catalogs

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
spec = importlib.util.spec_from_file_location("benchmark_runner", BENCHMARKS / "run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
audit_spec = importlib.util.spec_from_file_location("benchmark_auditor", BENCHMARKS / "verify_results.py")
auditor = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(auditor)


def test_manifest_has_sixty_distinct_immutable_repositories():
    rows = json.loads((BENCHMARKS / "manifest.json").read_text(encoding="utf-8"))["repositories"]
    assert len(rows) == len({row["repository_url"] for row in rows}) == 60
    assert Counter(row["language"] for row in rows) == {language: 10 for language in runner.LANGUAGES}
    assert all(len(row["commit"]) == 40 and set(row["commit"]) <= set("0123456789abcdef") for row in rows)
    assert {row["source_host"] for row in rows} <= {"bitbucket.org", "github.com"}
    assert all(row["source_host"] in row["repository_url"].split("/")[2] for row in rows)


def test_source_scan_is_not_reported_as_completed_test(tmp_path):
    data = json.loads((BENCHMARKS / "manifest.json").read_text(encoding="utf-8"))
    rows = [runner.initial_result(row) for row in data["repositories"]]
    rows[0].update(status="source_scanned", source_count=100)
    runner.render_reports(rows, tmp_path)
    result = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert result["summary"]["Java"] == {"source_scanned": 1, "pending": 9}
    assert "| Java | 0 | 0 | 10 |" in (tmp_path / "results.md").read_text(encoding="utf-8")
    assert result["repositories"][0]["fp"] is None
    assert result["repositories"][0]["fn"] is None


def test_source_inventory_ignores_manifests_declarations_and_untracked_build_outputs(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    for name, value in {"package.json": '{"name":"fixture"}', "pom.xml": "<project/>",
                        "Empty.java": "", "library.d.ts": "declare const version: string;"}.items():
        (tmp_path / name).write_text(value, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True, capture_output=True)
    (tmp_path / "generated.js").write_text("console.log('generated')", encoding="utf-8")
    assert auditor.source_file_inventory(tmp_path, "Java")["tracked_nonempty_language_files"] == 0
    assert auditor.source_file_inventory(tmp_path, "JavaScript")["tracked_nonempty_language_files"] == 0
    (tmp_path / "index.js").write_text("export const version = '1';", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "index.js"], check=True, capture_output=True)
    assert auditor.source_file_inventory(tmp_path, "JavaScript")["by_extension"] == {".js": 1}


def test_analyze_requires_real_final_publication(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "export_fixture", lambda *args: None)
    monkeypatch.setattr(runner, "run_command", lambda *args, **kwargs: "")
    with pytest.raises(RuntimeError, match="without final"):
        runner.analyze({"image_id": "sha256:" + "a" * 64, "image_reference": "docker.io/example:test"}, tmp_path, "rules", 60)


def test_analyze_rejects_failed_validation(monkeypatch, tmp_path):
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    for name, value in {
        "summary.json": {"cyclonedx_valid": False, "status": "succeeded"},
        "final.cdx.json": {"components": []}, "source.syft.json": {"artifacts": []},
        "image.syft.json": {"artifacts": []}, "decisions.json": [],
    }.items():
        (analysis / name).write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(runner, "run_command", lambda *args, **kwargs: "")
    with pytest.raises(RuntimeError, match="did not confirm validation"):
        runner.read_analysis({"image_id": "sha256:" + "a" * 64}, analysis, "rules")


def test_scoped_primary_identity_requires_ecosystem_namespace_and_exact_version():
    expected = {"language": "Java", "expected_package": "org.example:library", "expected_version": "1.2.3"}
    assert runner.expected_observed(expected, [{"purl": "pkg:maven/org.example/library@1.2.3"}]) is True
    assert runner.expected_observed(expected, [{"purl": "pkg:maven/other/library@1.2.3"}]) is False
    assert runner.expected_observed(expected, [{"purl": "pkg:maven/org.example/library@1.2.4"}]) is False
    assert runner.expected_observed({**expected, "expected_version": "unspecified"}, []) is None


def test_recipes_build_native_packages_and_never_push():
    for language in runner.LANGUAGES:
        dockerfile = runner.recipe({"language": language, "id": "example"})
        assert "push" not in dockerfile
        assert "COPY src/" in dockerfile
    assert "pip install" in runner.recipe({"language": "Python"})
    assert "cargo auditable build" in runner.recipe({"language": "Rust"})
    assert "go build" in runner.recipe({"language": "Go", "id": "example"})


def test_bitbucket_reader_does_not_load_admin_or_model_credentials(tmp_path):
    loader_spec = importlib.util.spec_from_file_location("benchmark_bb_reader", BENCHMARKS / "inspect_bitbucket.py")
    loader = importlib.util.module_from_spec(loader_spec)
    loader_spec.loader.exec_module(loader)
    env = tmp_path / ".env"
    env.write_text("BITBUCKET_WORKSPACE=fixture\nBITBUCKET_EMAIL=reader@example.test\nBITBUCKET_TOKEN=reader-token\n"
                   "BB_BOOTSTRAP_TOKEN=admin-token\nOPENAI_API_KEY=model-secret\n", encoding="utf-8")
    values = loader.credentials(env)
    assert set(values) == {"BITBUCKET_WORKSPACE", "BITBUCKET_EMAIL", "BITBUCKET_TOKEN"}


@pytest.fixture
def published_result(monkeypatch, tmp_path):
    """Real reconciliation/publication; fixed conversion fixture avoids Docker/network."""
    def publish(mode="rules"):
        config_digest = "sha256:" + "c" * 64
        image = {
            "artifacts": [{"id": "image-package", "name": "example", "version": "1", "type": "python",
                           "foundBy": "python-installed-package-cataloger", "locations": [], "licenses": [],
                           "language": "python", "cpes": [], "purl": "pkg:pypi/example@1"}],
            "artifactRelationships": [], "files": [],
            "source": {"id": "fixture-image", "name": "fixture", "version": "", "type": "image",
                       "metadata": {"imageID": config_digest}},
            "descriptor": {"name": "syft", "version": "1.51.1", "configuration": {}}, "distro": {},
            "schema": {"version": "16.1.10", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json"},
        }
        source = copy.deepcopy(image)
        source["artifacts"] = []
        ref = "pkg:pypi/example@1?package-id=image-package"
        cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "components": [{"type": "library", "bom-ref": ref, "name": "example", "version": "1",
                               "purl": "pkg:pypi/example@1"}], "dependencies": [{"ref": ref, "dependsOn": []}]}
        monkeypatch.setattr("sbom_creator.pipeline.convert", lambda *args: copy.deepcopy(cdx))
        assessor = rules_assessor
        if mode == "llm":
            class Opener:
                def open(self, request, timeout):
                    request_body = json.loads(request.data)
                    candidates = json.loads(request_body["messages"][1]["content"])["candidates"]
                    assessments = [{"candidate_id": c["candidate_id"], "tp_score": 91,
                                    "reason": "Installed image metadata", "missing_evidence": [],
                                    "evidence_ids": [e["id"] for e in c["evidence"]]} for c in candidates]
                    answer = {"model": "test", "choices": [{"finish_reason": "stop", "message": {
                        "content": json.dumps({"assessments": assessments})}}]}
                    return io.BytesIO(json.dumps(answer).encode())
            monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener())
            assessor = OpenAICompatibleAssessor(LlmConfig("", "http://127.0.0.1:12345/v1", "test"))
        row = {"language": "Python", "expected_package": "example", "expected_version": "1",
               "commit": "a" * 40, "image_id": "sha256:" + "b" * 64}
        output = tmp_path / ("published-" + mode)
        publish_catalogs(source, image, output, Settings(), assessor,
                         {"mode": mode, "git": {"commit": row["commit"]}, "image": {
                             "image_id": row["image_id"], "image_config_digest": config_digest}})
        runner.read_analysis(row, output, mode)
        return row, output
    return publish


def test_read_analysis_accepts_actual_llm_audit_mode(published_result):
    row, output = published_result("llm")
    provenance = json.loads((output / "provenance.json").read_text("utf-8"))
    assert provenance["assessment"]["mode"] == "llm"
    assert provenance["assessment"]["batches"][0]["reported_model"] == "test"
    assert row["status"] == "completed_llm"
    assert row["include"] == row["final_count"] == 1


@pytest.mark.parametrize("field,value", [("name", "different-package"), ("version", "999.0")])
def test_cache_hash_and_fresh_export_identity_both_reject_tampering(published_result, field, value):
    row, output = published_result()
    original_hash = row["final_sha256"]
    final_path = output / "final.cdx.json"
    cdx = json.loads(final_path.read_text("utf-8"))
    cdx["components"][0][field] = value
    final_path.write_text(json.dumps(cdx), encoding="utf-8")
    with pytest.raises(RuntimeError, match="fingerprint changed"):
        runner.read_analysis(row, output, "rules", expected_final_sha=original_hash)
    with pytest.raises(ValueError, match="differs from selected"):
        runner.read_analysis(row, output, "rules")
    assert row["final_sha256"] == original_hash


@pytest.mark.parametrize("name", ["selected.syft.json", "coverage.json"])
def test_read_analysis_requires_all_evidence_files(published_result, name):
    row, output = published_result()
    (output / name).unlink()
    with pytest.raises(FileNotFoundError):
        runner.read_analysis(row, output, "rules")


def test_read_analysis_rejects_stale_built_image_id(published_result):
    row, output = published_result()
    row["image_id"] = "sha256:" + "d" * 64
    with pytest.raises(RuntimeError, match="image ID differs"):
        runner.read_analysis(row, output, "rules")


@pytest.mark.parametrize("name,field,value,match", [
    ("coverage.json", "decisions", {"INCLUDE": 0, "EXCLUDE": 0, "UNKNOWN": 0}, "Decision counts"),
    ("coverage.json", "partial_inventory", False, "partial status"),
    ("summary.json", "selected_count", 0, "summary counts"),
])
def test_read_analysis_rejects_inconsistent_selection_and_coverage(published_result, name, field, value, match):
    row, output = published_result()
    path = output / name
    data = json.loads(path.read_text("utf-8"))
    data[field] = value
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RuntimeError, match=match):
        runner.read_analysis(row, output, "rules")


def test_direct_syft_benchmark_requires_exported_config_identity(published_result):
    row, output = published_result()
    path = output / "provenance.json"
    data = json.loads(path.read_text("utf-8"))
    row.pop("image_config_digest", None)
    data["image"]["acquisition_method"] = "syft-direct-v1"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RuntimeError, match="exported benchmark"):
        runner.read_analysis(row, output, "rules")
    row["image_config_digest"] = data["image"]["image_config_digest"]
    runner.read_analysis(row, output, "rules")

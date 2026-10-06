"""Default public paths must work with absent or unusable LLM configuration."""
import json
import time

from fastapi.testclient import TestClient
from test_pipeline import (
    real_catalogs as real_catalogs,  # noqa: PLC0414 -- expose shared pytest fixture
)

from sbom_creator import cli, pipeline
from sbom_creator.acquire import Settings
from sbom_creator.service import create_app


def forbid_model(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Default path attempted model configuration")
    monkeypatch.setattr(pipeline.LlmConfig, "from_environment", fail)
    monkeypatch.setenv("SBOM_LLM_BASE_URL", "invalid://must-not-be-read")
    monkeypatch.setenv("SBOM_LLM_API_KEY_FILE", "/missing/must-not-be-read")


def test_http_default_runs_real_publication_without_model(real_catalogs, tmp_path, monkeypatch):
    source, image, config = real_catalogs
    forbid_model(monkeypatch)
    monkeypatch.setenv("SBOM_API_TOKEN", "fixture-token")
    # Acquisition boundaries use already scanned fixtures; reconciliation and
    # pinned Syft conversion/publication run unmocked through the real API runner.
    monkeypatch.setattr(pipeline, "checkout", lambda *args: {"commit": "a" * 40})
    monkeypatch.setattr(pipeline, "scan_source", lambda *args: source)
    monkeypatch.setattr(pipeline, "scan_image", lambda *args: (image, {"test_fixture": True}))
    settings = Settings(syft_binary=config.syft_binary, bitbucket_hosts=("bitbucket.org",),
                        registry_hosts=("registry.example",))
    headers = {"Authorization": "Bearer fixture-token"}
    with TestClient(create_app(tmp_path, settings=settings)) as client:
        response = client.post("/v1/analyses", headers=headers, json={
            "repository_url": "https://bitbucket.org/fixture/app.git", "commit": "a" * 40,
            "image": "registry.example/fixture:1"})
        assert response.status_code == 202
        url = response.json()["status_url"]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = client.get(url, headers=headers).json()
            if state["status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.05)
        assert state["status"] == "succeeded", state
        assert state["result"]["assessment_mode"] == "rules"
        assert state["result"]["partial"] is True
        report = client.get(url + "/artifacts/review.json", headers=headers)
        assert report.status_code == 200
        assert report.json()["reason_counts"] == {"SOURCE_ONLY": 1}
        assert report.json()["schema_version"] == 2
        assert report.json()["group_counts"] == {"source_declarations": 1}
        assert state["result"]["unknown_groups"] == report.json()["group_counts"]
        final = client.get(url + "/artifacts/final.cdx.json", headers=headers).json()
        assert len(final["components"]) == 2
        properties = {p["name"]: p["value"] for p in final["metadata"]["properties"]}
        assert properties["sbom-creator:assessment-mode"] == "rules"
        assert properties["sbom-creator:coverage"] == "partial"


def test_cli_defaults_to_rules(monkeypatch, capsys):
    captured = {}
    def run(*args, **kwargs):
        captured.update(kwargs)
        return {"status": "succeeded"}
    monkeypatch.setattr(cli, "analyze_local", run)
    monkeypatch.setattr("sys.argv", ["sbom-creator", "analyze-local", "--source", ".",
                                    "--image", "docker.io/fixture:1", "--output", "unused"])
    assert cli.main() == 0
    assert captured["mode"] == "rules"
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"


def test_remote_api_rejects_local_archive_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_API_TOKEN", "fixture-token")
    with TestClient(create_app(tmp_path, settings=Settings(image_archive="/private/fixture.tar"))) as client:
        result = client.post("/v1/analyses", headers={"Authorization": "Bearer fixture-token"}, json={
            "repository_url": "https://bitbucket.org/fixture/app.git", "commit": "a" * 40,
            "image": "registry.example/app:1"})
        assert result.status_code == 503

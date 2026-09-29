import json
import time

from fastapi.testclient import TestClient

from sbom_creator.acquire import Settings
from sbom_creator.service import create_app

SETTINGS = Settings(bitbucket_hosts=("bitbucket.org",), registry_hosts=("registry.example",))
REQUEST = {"repository_url": "https://bitbucket.org/workspace/repository.git",
           "commit": "a" * 40, "image": "registry.example/app:1"}


def test_api_denies_no_configured_token(tmp_path, monkeypatch):
    monkeypatch.delenv("SBOM_API_TOKEN", raising=False)
    monkeypatch.delenv("SBOM_API_TOKEN_FILE", raising=False)
    with TestClient(create_app(tmp_path, settings=SETTINGS)) as client:
        assert client.post("/v1/analyses", json=REQUEST).status_code == 503


def test_missing_token_file_returns_configuration_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_API_TOKEN_FILE", str(tmp_path / "not-configured"))
    with TestClient(create_app(tmp_path, settings=SETTINGS)) as client:
        assert client.post("/v1/analyses", json=REQUEST).status_code == 503


def test_failed_job_blocks_artifacts_and_redacts_error(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_API_TOKEN", "test-token")

    def failing(*args, **kwargs):
        raise RuntimeError("secret-value-do-not-publish")

    with TestClient(create_app(tmp_path, failing, SETTINGS)) as client:
        assert client.post("/v1/analyses", json=REQUEST).status_code == 401
        headers = {"Authorization": "Bearer test-token"}
        response = client.post("/v1/analyses", json=REQUEST, headers=headers)
        assert response.status_code == 202
        path = response.json()["status_url"]
        for _ in range(100):
            response = client.get(path, headers=headers)
            if response.json()["status"] == "failed":
                break
            time.sleep(0.01)
        assert response.json()["status"] == "failed"
        assert "secret-value" not in response.text
        assert client.get(path + "/artifacts/final.cdx.json", headers=headers).status_code == 409


def test_successful_job_has_download_and_rejects_foreign_host(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_API_TOKEN", "test-token")

    def success(url, commit, image, output, **kwargs):
        assert kwargs["mode"] == "rules"
        output.mkdir()
        (output / "final.cdx.json").write_text('{"bomFormat":"CycloneDX"}', "utf-8")
        return {"status": "succeeded"}

    with TestClient(create_app(tmp_path, success, SETTINGS)) as client:
        headers = {"Authorization": "Bearer test-token"}
        invalid = dict(REQUEST, repository_url="https://evil.example/repo.git")
        assert client.post("/v1/analyses", json=invalid, headers=headers).status_code == 422
        response = client.post("/v1/analyses", json=REQUEST, headers=headers)
        path = response.json()["status_url"]
        for _ in range(100):
            state = client.get(path, headers=headers).json()
            if state["status"] == "succeeded":
                break
            time.sleep(0.01)
        assert state["status"] == "succeeded"
        assert client.get(path + "/artifacts/final.cdx.json", headers=headers).status_code == 200
        assert client.get(path + "/artifacts/secrets.json", headers=headers).status_code == 404


def test_restart_marks_incomplete_jobs_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_API_TOKEN", "test-token")
    directory = tmp_path / "jobs" / "11111111-1111-4111-8111-111111111111"
    directory.mkdir(parents=True)
    (directory / "status.json").write_text(json.dumps({"id": directory.name, "status": "running"}))
    with TestClient(create_app(tmp_path, settings=SETTINGS)) as client:
        response = client.get(f"/v1/analyses/{directory.name}",
                              headers={"Authorization": "Bearer test-token"})
        assert response.json()["error"] == "interrupted_by_restart"

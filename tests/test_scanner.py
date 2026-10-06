from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from sbom_creator import scanner
from sbom_creator.acquire import SYFT_VERSION, Settings

DIGEST = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
CONFIG = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"diff_ids": [DIGEST]}}).encode()
CONFIG_DIGEST = "sha256:" + hashlib.sha256(CONFIG).hexdigest()


def inventory():
    return {"artifacts": [], "descriptor": {"name": "syft", "version": SYFT_VERSION},
            "source": {"metadata": {"imageID": CONFIG_DIGEST}}}


def test_source_scan_ignores_repo_config_and_ambient_syft_env(tmp_path, monkeypatch):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / ".syft.yaml").write_text("enrich: [all]")
    monkeypatch.setenv("SYFT_ENRICH", "all")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[1] == "version":
            return json.dumps({"version": SYFT_VERSION})
        config = Path(args[args.index("--config") + 1])
        assert config.parent != checkout
        assert "use-packages-lib: false" in config.read_text()
        assert "SYFT_ENRICH" not in kwargs["env"]
        assert kwargs["cwd"] != checkout
        return json.dumps(inventory())

    monkeypatch.setattr(scanner, "run_command", fake_run)
    result = scanner.scan_source(checkout, tmp_path / "source.json", Settings())
    assert result == inventory()
    assert "directory" in calls[-1][0]
    assert "**/.git/**" in calls[-1][0]
    assert calls[-1][0][2] == f"dir:{checkout.resolve()}"


def test_wrong_syft_version_blocks_scan_and_output(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "run_command", lambda *args, **kwargs: '{"version":"1.0.0"}')
    with pytest.raises(RuntimeError, match="1.51.1"):
        scanner.scan_source(tmp_path, tmp_path / "source.json", Settings())
    assert not (tmp_path / "source.json").exists()


def test_invalid_scanner_output_not_published(tmp_path, monkeypatch):
    def fake_run(args, **kwargs):
        return json.dumps({"version": SYFT_VERSION}) if args[1] == "version" else "not json"
    monkeypatch.setattr(scanner, "run_command", fake_run)
    with pytest.raises(RuntimeError, match="invalid JSON"):
        scanner.scan_source(tmp_path, tmp_path / "source.json", Settings())
    assert not (tmp_path / "source.json").exists()


def registry_inventory():
    data = inventory()
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": CONFIG_DIGEST}}).encode()
    metadata = data["source"]["metadata"]
    metadata.update(manifest=base64.b64encode(manifest).decode(), config=base64.b64encode(CONFIG).decode(),
        manifestDigest="sha256:" + hashlib.sha256(manifest).hexdigest(),
        os="linux", architecture="amd64", layers=[{"digest": DIGEST}], repoDigests=[])
    return data


def test_direct_registry_no_daemon_and_private_contents_not_published(tmp_path, monkeypatch):
    calls = []
    data = registry_inventory()
    data["files"] = [{"location": {"path": "/unused"}, "contents": "c2VjcmV0"}]
    data["descriptor"]["configuration"] = {"password": "private", "catalogers": {"used": ["file-content-cataloger"]}}
    def fake(args, **kwargs):
        calls.append((args, kwargs))
        if args[1] == "version":
            return json.dumps({"version": SYFT_VERSION})
        assert args[2] == "registry:registry.example/app:latest"
        assert "--platform" in args
        assert "DOCKER_HOST" not in kwargs["env"]
        assert kwargs["env"]["SYFT_REGISTRY_AUTH_PASSWORD"] == "fixture-secret"
        assert "fixture-secret" not in str(args)
        assert kwargs["monitored_paths"]
        return json.dumps(data)
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted:2375")
    monkeypatch.setenv("SBOM_REGISTRY_USERNAME", "fixture-user")
    monkeypatch.setenv("SBOM_REGISTRY_PASSWORD", "fixture-secret")
    monkeypatch.setattr(scanner, "run_command", fake)
    output = tmp_path / "image.json"
    _, provenance = scanner.scan_image("registry.example/app:latest", output,
        Settings(registry_hosts=("registry.example",)))
    assert all(args[0] == "syft" for args, _ in calls)
    assert "contents" not in output.read_text() and "private" not in output.read_text()
    assert json.loads(output.read_text())["descriptor"]["configuration"] == {"catalogers": {"used": ["file-content-cataloger"]}}
    assert provenance["acquisition_method"] == "syft-direct-v1"
    assert provenance["container_started"] is False


@pytest.mark.parametrize("field,value", [("imageID", DIGEST), ("manifestDigest", DIGEST),
    ("architecture", "arm64"), ("manifest", "not base64"), ("layers", [])])
def test_invalid_identity_never_publishes(tmp_path, monkeypatch, field, value):
    data = registry_inventory()
    data["source"]["metadata"][field] = value
    monkeypatch.setattr(scanner, "_syft", lambda *a, **k: data)
    output = tmp_path / "image.json"
    with pytest.raises((RuntimeError, ValueError)):
        scanner.scan_image("registry.example/app:latest", output, Settings(registry_hosts=("registry.example",)))
    assert not output.exists()


def test_wrong_requested_digest_blocks_output(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_syft", lambda *a, **k: registry_inventory())
    with pytest.raises(RuntimeError, match="Requested registry digest"):
        scanner.scan_image("registry.example/app@" + DIGEST, tmp_path / "out",
                          Settings(registry_hosts=("registry.example",)))


def test_parent_index_digest_is_accepted(tmp_path, monkeypatch):
    data = registry_inventory()
    data["source"]["metadata"]["repoDigests"] = ["registry.example/app@" + DIGEST]
    monkeypatch.setattr(scanner, "_syft", lambda *a, **k: data)
    scanner.scan_image("registry.example/app@" + DIGEST, tmp_path / "out",
                      Settings(registry_hosts=("registry.example",)))


def test_archive_mode_is_explicit_and_has_no_registry_claim(tmp_path, monkeypatch):
    archive = tmp_path / "fixture.tar"
    archive.write_bytes(b"fixture")
    def fake(args, *a, **k):
        assert args[1] == "docker-archive:" + str(archive.resolve())
        return registry_inventory()
    monkeypatch.setattr(scanner, "_syft", fake)
    _, provenance = scanner.scan_image("registry.example/app:fixture", tmp_path / "out",
        Settings(registry_hosts=("registry.example",), image_archive=str(archive)))
    assert provenance["registry_digest"] is None
    assert provenance["acquisition"] == "archive"


def test_convert_pins_cyclonedx_16(tmp_path, monkeypatch):
    source = tmp_path / "selected.syft.json"
    source.write_text(json.dumps(inventory()))
    calls = []
    def fake_run(args, **kwargs):
        calls.append(args)
        return (json.dumps({"version": SYFT_VERSION}) if args[1] == "version"
                else '{"bomFormat":"CycloneDX","specVersion":"1.6"}')
    monkeypatch.setattr(scanner, "run_command", fake_run)
    result = scanner.convert(source, tmp_path / "final.json", Settings())
    assert result["specVersion"] == "1.6"
    assert "cyclonedx-json@1.6" in calls[-1]


def test_archive_empty_summary_platform_uses_verified_config(tmp_path, monkeypatch):
    data = registry_inventory()
    data["source"]["metadata"].update(os="", architecture="")
    monkeypatch.setattr(scanner, "_syft", lambda *a, **k: data)
    archive = tmp_path / "fixture.tar"
    archive.write_bytes(b"fixture")
    _, provenance = scanner.scan_image("registry.example/app:fixture", tmp_path / "out",
        Settings(registry_hosts=("registry.example",), image_archive=str(archive)))
    assert provenance["platform"] == "linux/amd64"


def test_registry_missing_credentials_pair_fails_before_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_REGISTRY_USERNAME", "fixture")
    monkeypatch.delenv("SBOM_REGISTRY_PASSWORD", raising=False)
    monkeypatch.delenv("SBOM_REGISTRY_PASSWORD_FILE", raising=False)
    monkeypatch.setattr(scanner, "run_command", lambda *a, **k: pytest.fail("must not invoke scanner"))
    with pytest.raises(ValueError, match="both"):
        scanner.scan_image("registry.example/app:1", tmp_path / "out", Settings(registry_hosts=("registry.example",)))


def test_scan_failure_does_not_publish_intermediate_contents(tmp_path, monkeypatch):
    def fail(args, **kwargs):
        if args[1] == "version":
            return json.dumps({"version": SYFT_VERSION})
        assert kwargs["timeout"] == 3
        raise RuntimeError("Syft timed out")
    monkeypatch.setattr(scanner, "run_command", fail)
    with pytest.raises(RuntimeError, match="timed out"):
        scanner.scan_image("registry.example/app:1", tmp_path / "out",
            Settings(registry_hosts=("registry.example",), image_timeout=3))
    assert not (tmp_path / "out").exists()

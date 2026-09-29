from __future__ import annotations

import hashlib
import io
import json
import tarfile
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


def test_platform_manifest_selection_is_exact():
    manifest = {"manifests": [
        {"digest": DIGEST, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": "sha256:" + "c" * 64, "platform": {"os": "linux", "architecture": "arm64"}}]}
    assert scanner._platform_digest(manifest, "linux/amd64") == DIGEST
    with pytest.raises(RuntimeError, match="unambiguous"):
        scanner._platform_digest(manifest, "linux/s390x")
    manifest["manifests"].append(manifest["manifests"][0])
    with pytest.raises(RuntimeError, match="unambiguous"):
        scanner._platform_digest(manifest, "linux/amd64")


def fake_docker(monkeypatch, calls, wrong_image=False):
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "manifest":
            return json.dumps({"manifests": [{"digest": DIGEST,
                "platform": {"os": "linux", "architecture": "amd64"}}]})
        if args[1] == "pull":
            return f"Digest: {DIGEST}\nStatus: downloaded"
        if args[1:3] == ["image", "inspect"]:
            return json.dumps({"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64",
                               "RepoDigests": ["registry.example/app@" + DIGEST],
                               "RootFS": {"Layers": [DIGEST]}})
        if args[1:3] == ["image", "save"]:
            with tarfile.open(Path(args[args.index("--output") + 1]), "w") as archive:
                for name, data in (("manifest.json", b'[{"Config":"config.json"}]'), ("config.json", CONFIG)):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            return ""
        raise AssertionError(args)

    def syft(args, settings, *, output):
        data = inventory()
        if wrong_image:
            data["source"]["metadata"]["imageID"] = "sha256:" + "c" * 64
        output.write_text(json.dumps(data))
        return data
    monkeypatch.setattr(scanner, "run_command", run)
    monkeypatch.setattr(scanner, "_syft", syft)


def test_image_resolved_by_platform_digest_then_saved_by_immutable_id(tmp_path, monkeypatch):
    calls = []
    fake_docker(monkeypatch, calls)
    result, provenance = scanner.scan_image("registry.example/app:latest", tmp_path / "image.json",
                                            Settings(registry_hosts=("registry.example",)))
    assert result == inventory()
    pull = next(args for args in calls if args[1] == "pull")
    assert pull[-1] == "registry.example/app@" + DIGEST
    save = next(args for args in calls if args[1:3] == ["image", "save"])
    assert save[-1] == IMAGE_ID
    assert provenance["image_id"] == IMAGE_ID
    assert provenance["image_config_digest"] == CONFIG_DIGEST
    assert provenance["platform_digest"] == DIGEST
    assert provenance["container_started"] is False
    assert len(provenance["archive_sha256"]) == 64
    assert all("run" not in args and "create" not in args for args in calls)


def test_local_image_mode_does_not_claim_registry_digest(tmp_path, monkeypatch):
    calls = []
    fake_docker(monkeypatch, calls)
    _, provenance = scanner.scan_image("registry.example/app:test", tmp_path / "image.json",
        Settings(registry_hosts=("registry.example",), pull_image=False))
    assert provenance["acquisition"] == "local"
    assert provenance["registry_digest"] is None
    assert provenance["platform_digest"] is None
    assert provenance["immutable_reference"] == IMAGE_ID
    assert all(args[1] not in ("pull", "manifest") for args in calls)


def test_wrong_archive_identity_blocks_output(tmp_path, monkeypatch):
    fake_docker(monkeypatch, [], wrong_image=True)
    output = tmp_path / "image.json"
    with pytest.raises(RuntimeError, match="identity"):
        scanner.scan_image("registry.example/app:latest", output,
                           Settings(registry_hosts=("registry.example",)))
    assert not output.exists()


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

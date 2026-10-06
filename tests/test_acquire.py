from __future__ import annotations

import base64
import os
import sys

import pytest

from sbom_creator import acquire
from sbom_creator.acquire import Settings

SHA = "a" * 40
URL = "https://bitbucket.example/scm/team/app.git"


@pytest.fixture
def settings():
    return Settings(bitbucket_hosts=("bitbucket.example",), registry_hosts=("registry.example",))


@pytest.mark.parametrize("url", ["http://bitbucket.example/a.git", "https://bitbucket.example.evil/a.git",
    "https://user:token@bitbucket.example/a.git", "https://bitbucket.example/a.git?token=secret",
    "https://bitbucket.example/a.git#x", "https://bitbucket.example\\evil/a.git", "https://bitbucket.example/\na"])
def test_repository_allowlist_is_exact_and_credentials_forbidden(settings, url):
    with pytest.raises(ValueError):
        acquire.validate_repository_url(url, settings)


def test_empty_allowlists_fail_closed():
    with pytest.raises(ValueError):
        acquire.validate_repository_url(URL, Settings())
    with pytest.raises(ValueError):
        acquire.image_reference("registry.example/app:1", Settings())


@pytest.mark.parametrize("reference", ["registry.example/app", "evil.example/app:1", "registry.example/app@sha256:123",
    "registry.example/app:tag --help", "registry.example/../app:1", "registry.example/-flag:1"])
def test_image_rejects_implicit_tags_untrusted_hosts_and_invalid_input(settings, reference):
    with pytest.raises(ValueError):
        acquire.image_reference(reference, settings)


def test_settings_env_is_explicit_and_boolean_parsed(monkeypatch):
    monkeypatch.setenv("SBOM_BITBUCKET_HOSTS", "bb.example, Bb2.example")
    monkeypatch.setenv("SBOM_IMAGE_ARCHIVE", "fixture.tar")
    monkeypatch.setenv("SBOM_SCAN_TIMEOUT", "77")
    settings = Settings.from_env()
    assert settings.bitbucket_hosts == ("bb.example", "bb2.example")
    assert settings.image_archive == "fixture.tar"
    assert settings.scan_timeout == 77
    monkeypatch.setenv("SBOM_PULL_IMAGE", "yes")
    with pytest.raises(ValueError):
        Settings.from_env()


def test_child_environment_has_no_unrelated_service_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-pass")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-pass")
    monkeypatch.setenv("SBOM_BITBUCKET_TOKEN", "do-not-pass")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    environment = acquire.clean_environment()
    assert "OPENAI_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "SBOM_BITBUCKET_TOKEN" not in environment
    assert environment["HTTPS_PROXY"] == "http://proxy.example:3128"
    assert "DOCKER_HOST" not in environment


def test_checkout_exact_commit_isolated_config_and_secret_never_in_argv(tmp_path, monkeypatch, settings):
    calls = []
    monkeypatch.setenv("SBOM_BITBUCKET_TOKEN", "private-token")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "credential.helper=malicious")

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SHA if args[1] == "rev-parse" else ""

    monkeypatch.setattr(acquire, "run_command", fake_run)
    result = acquire.checkout(URL, SHA.upper(), tmp_path / "checkout", settings)
    assert result["commit"] == SHA
    assert result["build_link"] == "unverified"
    assert result["coverage"]["source_build_executed"] is False
    assert [call[0][1] for call in calls] == ["init", "remote", "fetch", "checkout", "rev-parse"]
    assert "--detach" in calls[3][0]
    assert "private-token" not in repr([call[0] for call in calls])
    environment = calls[0][1]["env"]
    assert "GIT_CONFIG_PARAMETERS" not in environment
    config = {environment[f"GIT_CONFIG_KEY_{i}"]: environment[f"GIT_CONFIG_VALUE_{i}"]
              for i in range(int(environment["GIT_CONFIG_COUNT"]))}
    assert config["http.followRedirects"] == "false"
    assert config["protocol.allow"] == "never"
    assert config["protocol.https.allow"] == "always"
    assert config["credential.helper"] == ""
    assert config[f"http.{URL}.extraHeader"] == "Authorization: Bearer private-token"


def test_checkout_rejects_wrong_head(tmp_path, monkeypatch, settings):
    monkeypatch.setattr(acquire, "run_command", lambda *args, **kwargs: "b" * 40)
    with pytest.raises(RuntimeError, match="HEAD"):
        acquire.checkout(URL, SHA, tmp_path / "checkout", settings)


def test_bitbucket_cloud_basic_auth_is_environment_only(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_BITBUCKET_TOKEN", "cloud-secret")
    monkeypatch.delenv("SBOM_BITBUCKET_USERNAME", raising=False)
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs["env"]))
        return SHA if args[1] == "rev-parse" else ""
    monkeypatch.setattr(acquire, "run_command", fake_run)
    acquire.checkout(URL, SHA, tmp_path / "checkout", Settings(
        bitbucket_hosts=("bitbucket.example",), bitbucket_auth_mode="basic"))
    expected = "Authorization: Basic " + base64.b64encode(b"x-bitbucket-api-token-auth:cloud-secret").decode()
    assert expected in calls[0][1].values()
    assert "cloud-secret" not in repr([call[0] for call in calls])


def test_coverage_reports_skipped_lfs_and_submodules(tmp_path, settings):
    (tmp_path / ".gitmodules").write_text('[submodule "nested"]')
    (tmp_path / "model.bin").write_bytes(b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1\n")
    coverage = acquire.inspect_checkout(tmp_path, settings)
    assert coverage["gitmodules_present"] is True
    assert coverage["submodules_fetched"] is False
    assert coverage["lfs_pointer_paths"] == ["model.bin"]


def test_escaping_symlink_rejected(tmp_path, settings):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("secret")
    try:
        (root / "escape").symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks requires privilege on this host")
    with pytest.raises(ValueError, match="outside"):
        acquire.inspect_checkout(root, settings)


def test_bounded_runner_does_not_leak_diagnostics(tmp_path):
    with pytest.raises(RuntimeError) as failure:
        acquire.run_command([sys.executable, "-c", "import sys;sys.stderr.write('SECRET');sys.exit(2)"],
            cwd=tmp_path, env=os.environ.copy(), timeout=10, max_output_bytes=4096, label="Child")
    assert "SECRET" not in str(failure.value)
    assert "exit 2" in str(failure.value)


def test_bounded_runner_rejects_large_output(tmp_path):
    with pytest.raises(RuntimeError, match="output limit"):
        acquire.run_command([sys.executable, "-c", "print('x'*100000)"], cwd=tmp_path,
            env=os.environ.copy(), timeout=10, max_output_bytes=1024, label="Child")


def test_bounded_runner_times_out(tmp_path):
    with pytest.raises(RuntimeError, match="timed out"):
        acquire.run_command([sys.executable, "-c", "import time;time.sleep(10)"], cwd=tmp_path,
            env=os.environ.copy(), timeout=1, max_output_bytes=1024, label="Child")

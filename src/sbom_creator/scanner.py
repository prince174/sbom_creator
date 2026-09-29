"""Pinned Syft scans and immutable image acquisition; never start an image."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .acquire import (
    SYFT_VERSION,
    Settings,
    clean_environment,
    image_reference,
    inspect_checkout,
    run_command,
    secret,
)

TRUSTED_CONFIG = """check-for-app-update: false
parallelism: 2
enrich: []
java:
  use-network: false
  use-maven-local-repository: false
  resolve-transitive-dependencies: false
golang:
  search-remote-licenses: false
  search-local-mod-cache-licenses: false
  search-local-vendor-licenses: false
  use-packages-lib: false
javascript:
  search-remote-licenses: false
python:
  search-remote-licenses: false
  guess-unpinned-requirements: false
cpp:
  vcpkg-allow-git-clone: false
"""


def _json(value: str, label: str) -> dict[str, Any]:
    try:
        data = json.loads(value)
    except (json.JSONDecodeError, RecursionError):
        raise RuntimeError(f"{label} returned invalid JSON") from None
    if not isinstance(data, dict):
        raise TypeError(f"{label} requires a JSON object")
    return data


def _syft(args: list[str], settings: Settings, *, output: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sbom-syft-") as directory:
        root = Path(directory)
        config = root / "syft.yaml"
        config.write_text(TRUSTED_CONFIG, encoding="utf-8")
        environment = clean_environment()
        environment.update({"HOME": directory, "USERPROFILE": directory, "XDG_CONFIG_HOME": directory,
                            "XDG_CACHE_HOME": directory, "SYFT_CHECK_FOR_APP_UPDATE": "false"})
        version = _json(run_command([settings.syft_binary, "version", "-o", "json"],
                                    cwd=root, env=environment, timeout=30,
                                    max_output_bytes=settings.max_output_bytes, label="Syft version"),
                        "Syft version").get("version")
        if version != SYFT_VERSION:
            raise RuntimeError(f"Syft {SYFT_VERSION} is required; installed version differs")
        result = run_command([settings.syft_binary, *args, "--config", str(config)], cwd=root,
                             env=environment, timeout=settings.scan_timeout,
                             max_output_bytes=settings.max_sbom_bytes, label="Syft")
        data = _json(result, "Syft")
        if args[0] == "scan":
            if not isinstance(data.get("artifacts"), list):
                raise RuntimeError("Syft inventory requires an artifacts array")
            descriptor = data.get("descriptor", {})
            if descriptor.get("name") != "syft" or descriptor.get("version") != SYFT_VERSION:
                raise RuntimeError("Syft inventory descriptor does not match the pinned scanner")
        elif data.get("bomFormat") != "CycloneDX" or data.get("specVersion") != "1.6":
            raise RuntimeError("Syft conversion did not produce CycloneDX 1.6")
        output.parent.mkdir(parents=True, exist_ok=True)
        # Publish a complete JSON file only, after command success and basic validation.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".tmp",
                                         dir=output.parent, delete=False) as stream:
            pending = Path(stream.name)
            stream.write(result + "\n")
        try:
            pending.replace(output)
        finally:
            pending.unlink(missing_ok=True)
        return data


def scan_source(checkout: Path, output: Path, settings: Settings) -> dict[str, Any]:
    root = checkout.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source scan requires a checkout directory")
    inspect_checkout(root, settings)
    return _syft(["scan", f"dir:{root}", "--base-path", str(root), "--override-default-catalogers", "directory",
                  "--exclude", "**/.git/**", "--scope", "squashed", "-o", "syft-json"],
                 settings, output=output)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _archive_config_digest(archive: Path, inspected: dict[str, Any]) -> str:
    """Docker containerd IDs may be indexes; Syft imageID is the config digest."""
    with tarfile.open(archive, "r:*") as saved:
        def read_member(name: str) -> bytes:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Image archive contains an unsafe metadata path")
            try:
                member = saved.getmember(name)
            except KeyError:
                raise RuntimeError("Image archive metadata is missing") from None
            if not member.isfile() or member.size > 8 * 1024 * 1024:
                raise RuntimeError("Image archive metadata exceeds limits")
            stream = saved.extractfile(member)
            if stream is None:
                raise RuntimeError("Image archive metadata is unreadable")
            return stream.read(8 * 1024 * 1024 + 1)

        try:
            manifests = json.loads(read_member("manifest.json"))
        except json.JSONDecodeError:
            raise RuntimeError("Invalid image archive manifest") from None
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise RuntimeError("Image archive must contain exactly one platform image")
        config_name = manifests[0].get("Config")
        if not isinstance(config_name, str):
            raise TypeError("Image archive does not identify its configuration")
        content = read_member(config_name)
        config = _json(content.decode("utf-8"), "Image archive configuration")
        if (config.get("os") != inspected.get("Os")
                or config.get("architecture") != inspected.get("Architecture")
                or config.get("rootfs", {}).get("diff_ids") != inspected.get("RootFS", {}).get("Layers")):
            raise RuntimeError("Saved image configuration differs from inspected immutable image")
        return "sha256:" + hashlib.sha256(content).hexdigest()


def _platform_digest(manifest: dict[str, Any], platform: str) -> str | None:
    manifests = manifest.get("manifests")
    if manifests is None:
        if not isinstance(manifest.get("config"), dict):
            raise RuntimeError("Registry returned neither an image manifest nor an image index")
        return None
    if not isinstance(manifests, list):
        raise TypeError("Registry returned malformed image index")
    os_name, architecture, *variant = platform.split("/")
    expected_variant = variant[0] if variant else ""
    matches = [entry.get("digest") for entry in manifests if isinstance(entry, dict)
               and entry.get("platform", {}).get("os") == os_name
               and entry.get("platform", {}).get("architecture") == architecture
               and (not expected_variant or entry.get("platform", {}).get("variant", "") == expected_variant)]
    if len(matches) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(matches[0])):
        raise RuntimeError("Image index must have one unambiguous manifest for the configured platform")
    return str(matches[0])


def scan_image(image: str, output: Path, settings: Settings) -> tuple[dict[str, Any], dict[str, Any]]:
    reference = image_reference(image, settings)
    with tempfile.TemporaryDirectory(prefix="sbom-image-") as directory:
        root = Path(directory)
        docker_config = root / "docker"
        docker_config.mkdir()
        environment = clean_environment()
        # Keep daemon transport settings, but use no ambient credential helper/plugin config.
        environment.pop("DOCKER_CONFIG", None)
        environment["DOCKER_CONFIG"] = str(docker_config)
        username = secret("SBOM_REGISTRY_USERNAME")
        password = secret("SBOM_REGISTRY_PASSWORD")
        if bool(username) != bool(password):
            raise ValueError("Registry username and password must both be configured")
        auths: dict[str, Any] = {}
        if username:
            auths[reference.split("/", 1)[0]] = {
                "auth": base64.b64encode(f"{username}:{password}".encode()).decode()}
        config_path = docker_config / "config.json"
        config_path.write_text(json.dumps({"auths": auths}), encoding="utf-8")
        config_path.chmod(0o600)

        def docker(*args: str, monitored_paths: tuple[tuple[Path, int], ...] = ()) -> str:
            return run_command([settings.docker_binary, *args], cwd=root, env=environment,
                               timeout=settings.image_timeout, max_output_bytes=settings.max_output_bytes,
                               label=f"Docker {args[0]}", monitored_paths=monitored_paths)

        platform_digest = None
        immutable_reference = reference
        if settings.pull_image:
            manifest = _json(docker("manifest", "inspect", reference), "Image manifest")
            platform_digest = _platform_digest(manifest, settings.image_platform)
            repository = reference.split("@", 1)[0]
            if ":" in repository.rsplit("/", 1)[-1]:
                repository = repository.rsplit(":", 1)[0]
            pull_reference = f"{repository}@{platform_digest}" if platform_digest else reference
            pull_output = docker("pull", "--platform", settings.image_platform, pull_reference)
            digests = re.findall(r"(?m)^Digest:\s*(sha256:[0-9a-f]{64})\s*$", pull_output)
            if len(set(digests)) != 1:
                raise RuntimeError("Docker pull did not report one immutable registry digest")
            pulled_digest = digests[0]
            if platform_digest and platform_digest != pulled_digest:
                raise RuntimeError("Pulled digest differs from the selected platform manifest")
            requested_digest = reference.split("@", 1)[1] if "@" in reference else None
            if platform_digest is None and requested_digest and requested_digest != pulled_digest:
                raise RuntimeError("Pulled digest differs from the requested digest")
            platform_digest = platform_digest or pulled_digest
            immutable_reference = f"{repository}@{platform_digest}"
        inspect = _json(docker("image", "inspect", immutable_reference, "--format", "{{json .}}"),
                        "Docker image inspect")
        image_id = inspect.get("Id", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise RuntimeError("Docker image has no immutable local image ID")
        if not settings.pull_image:
            immutable_reference = image_id
        actual_platform = f"{inspect.get('Os', '')}/{inspect.get('Architecture', '')}"
        if inspect.get("Variant"):
            actual_platform += f"/{inspect['Variant']}"
        requested_parts = settings.image_platform.split("/")
        if actual_platform.split("/")[:len(requested_parts)] != requested_parts:
            raise RuntimeError("Pulled image platform differs from the configured platform")
        archive = root / "image.tar"
        docker("image", "save", "--platform", settings.image_platform, "--output", str(archive), image_id,
               monitored_paths=((archive, settings.max_archive_bytes),))
        if not archive.is_file() or archive.stat().st_size == 0:
            raise RuntimeError("Docker did not create a readable image archive")
        archive_sha256 = _sha256(archive)
        config_digest = _archive_config_digest(archive, inspect)
        data = _syft(["scan", f"docker-archive:{archive}", "--override-default-catalogers", "image",
                      "--scope", "squashed", "-o", "syft-json"], settings, output=output)
        metadata = data.get("source", {}).get("metadata", {})
        if metadata.get("imageID") != config_digest:
            output.unlink(missing_ok=True)
            raise RuntimeError("Syft scanned image identity does not match the saved image configuration")
        provenance = {"image": reference, "immutable_reference": immutable_reference,
                      "image_digest": platform_digest or image_id, "platform_digest": platform_digest,
                      "registry_digest": platform_digest,
                      "acquisition": "registry" if settings.pull_image else "local",
                      "image_id": image_id, "requested_platform": settings.image_platform,
                      "image_config_digest": config_digest,
                      "platform": actual_platform, "repo_digests": inspect.get("RepoDigests", []),
                      "archive_sha256": archive_sha256, "syft_version": SYFT_VERSION,
                      "scope": "squashed", "container_started": False, "build_link": "unverified"}
        return data, provenance


def convert(selected_path: Path, output_path: Path, settings: Settings) -> dict[str, Any]:
    source = selected_path.resolve(strict=True)
    if source.stat().st_size > settings.max_sbom_bytes:
        raise ValueError("Selected SBOM exceeds size limit")
    return _syft(["convert", str(source), "-o", "cyclonedx-json@1.6"], settings, output=output_path)

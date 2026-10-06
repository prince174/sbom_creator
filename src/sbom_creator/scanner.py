"""Pinned Syft scans and immutable image acquisition; never start an image."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tempfile
from pathlib import Path
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
from .payload import collect as collect_payload

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


IMAGE_CONFIG = """
file:
  metadata:
    selection: all
  content:
    skip-files-above-size: 33554432
    globs:
      - "**/RECORD"
      - "**/package.json"
      - "**/*.jar"
      - "**/*.war"
      - "**/*.ear"
      - "**/*.zip"
      - "**/*.hpi"
      - "**/*.jpi"
      - "**/*.nar"
      - "**/*.jmod"
registry:
  insecure-skip-tls-verify: false
  insecure-use-http: false
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
        image_scan = args[0] == "scan" and args[1].startswith(("registry:", "docker-archive:", "oci-archive:"))
        config.write_text(TRUSTED_CONFIG + (IMAGE_CONFIG if image_scan else ""), encoding="utf-8")
        environment = clean_environment()
        environment.update({"HOME": directory, "USERPROFILE": directory, "XDG_CONFIG_HOME": directory,
                            "XDG_CACHE_HOME": directory, "SYFT_CHECK_FOR_APP_UPDATE": "false"})
        environment.update({"TMPDIR": directory, "TMP": directory, "TEMP": directory, "DOCKER_CONFIG": directory})
        if image_scan and args[1].startswith("registry:"):
            username, password = secret("SBOM_REGISTRY_USERNAME"), secret("SBOM_REGISTRY_PASSWORD")
            if bool(username) != bool(password):
                raise ValueError("Registry username and password must both be configured")
            if username:
                environment.update(SYFT_REGISTRY_AUTH_AUTHORITY=args[1].removeprefix("registry:").split("/")[0],
                                   SYFT_REGISTRY_AUTH_USERNAME=username, SYFT_REGISTRY_AUTH_PASSWORD=password)
        version = _json(run_command([settings.syft_binary, "version", "-o", "json"],
                                    cwd=root, env=environment, timeout=30,
                                    max_output_bytes=settings.max_output_bytes, label="Syft version"),
                        "Syft version").get("version")
        if version != SYFT_VERSION:
            raise RuntimeError(f"Syft {SYFT_VERSION} is required; installed version differs")
        result = run_command([settings.syft_binary, *args, "--config", str(config)], cwd=root,
                             env=environment, timeout=min(settings.scan_timeout, settings.image_timeout) if image_scan else settings.scan_timeout,
                             max_output_bytes=settings.max_sbom_bytes, label="Syft",
                             monitored_paths=((root, settings.max_archive_bytes),), max_files=settings.max_checkout_files)
        data = _json(result, "Syft")
        if args[0] == "scan":
            if not isinstance(data.get("artifacts"), list):
                raise RuntimeError("Syft inventory requires an artifacts array")
            descriptor = data.get("descriptor", {})
            if descriptor.get("name") != "syft" or descriptor.get("version") != SYFT_VERSION:
                raise RuntimeError("Syft inventory descriptor does not match the pinned scanner")
        elif data.get("bomFormat") != "CycloneDX" or data.get("specVersion") != "1.6":
            raise RuntimeError("Syft conversion did not produce CycloneDX 1.6")
        if image_scan:
            # Private intermediate: the caller validates identity and strips file contents.
            return data
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


def _image_identity(data: dict, reference: str, settings: Settings) -> dict:
    metadata = data.get("source", {}).get("metadata", {})
    def decode(field):
        encoded = metadata.get(field)
        if not isinstance(encoded, str) or len(encoded) > 12 * 1024 * 1024:
            raise RuntimeError("Missing or oversized image identity metadata")
        raw = base64.b64decode(encoded, validate=True)
        return raw, _json(raw.decode("utf-8"), "Image " + field)
    raw_manifest, manifest = decode("manifest")
    raw_config, config = decode("config")
    manifest_digest = "sha256:" + hashlib.sha256(raw_manifest).hexdigest()
    config_digest = "sha256:" + hashlib.sha256(raw_config).hexdigest()
    if (metadata.get("manifestDigest") != manifest_digest
            or metadata.get("imageID") != config_digest
            or manifest.get("config", {}).get("digest") != config_digest):
        raise RuntimeError("Syft image identity hashes do not match")
    actual = "/".join(filter(None, (config.get("os"), config.get("architecture"), config.get("variant"))))
    requested = settings.image_platform.split("/")
    if actual.split("/")[:len(requested)] != requested:
        raise RuntimeError("Image platform differs from the configured platform")
    if any(metadata.get(key) != config.get(key) for key in ("os", "architecture")
           if not settings.image_archive or metadata.get(key)):
        raise RuntimeError("Syft image platform metadata is inconsistent")
    diff_ids = config.get("rootfs", {}).get("diff_ids")
    layers = metadata.get("layers", [])
    if not isinstance(diff_ids, list) or diff_ids != [layer.get("digest") for layer in layers]:
        raise RuntimeError("Syft image layer identities are inconsistent")
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in diff_ids):
        raise RuntimeError("Invalid layer identity")
    repository = reference.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    repo_digests = metadata.get("repoDigests", [])
    if not settings.image_archive and "@" in reference:
        requested_digest = reference.split("@", 1)[1]
        # Syft exposes the resolved platform manifest and parent index in repoDigests.
        if requested_digest != manifest_digest and not any(
                value.rsplit("@", 1)[-1] == requested_digest for value in repo_digests):
            raise RuntimeError("Requested registry digest differs from scanned image")
    return {"image": reference, "immutable_reference": repository + "@" + manifest_digest,
            "image_digest": manifest_digest, "platform_digest": manifest_digest,
            "registry_digest": manifest_digest if not settings.image_archive else None,
            "acquisition": "archive" if settings.image_archive else "registry",
            "image_id": config_digest, "image_config_digest": config_digest,
            "requested_platform": settings.image_platform, "platform": actual,
            "repo_digests": repo_digests, "syft_version": SYFT_VERSION,
            "scope": "squashed", "container_started": False, "build_link": "unverified",
            "acquisition_method": "syft-direct-v1"}


def scan_image(image: str, output: Path, settings: Settings) -> tuple[dict[str, Any], dict[str, Any]]:
    reference = image_reference(image, settings)
    target = "registry:" + reference
    if settings.image_archive:
        archive = Path(settings.image_archive).resolve(strict=True)
        if not archive.is_file() or archive.stat().st_size > settings.max_archive_bytes:
            raise ValueError("Local image archive is invalid or oversized")
        target = "docker-archive:" + str(archive)
    data = _syft(["scan", target, "--platform", settings.image_platform,
                  "--override-default-catalogers", "image", "--scope", "squashed", "-o", "syft-json"],
                 settings, output=output)
    provenance = _image_identity(data, reference, settings)
    provenance["payload_evidence"] = collect_payload(data)
    for entry in data.get("files", []):
        entry.pop("contents", None)
    # Syft embeds its effective configuration. Do not export credential-bearing configuration.
    descriptor = data.get("descriptor", {})
    configuration = descriptor.pop("configuration", {})
    catalogers = configuration.get("catalogers", {}) if isinstance(configuration, dict) else {}
    used = catalogers.get("used", []) if isinstance(catalogers, dict) else []
    if isinstance(used, list) and used and all(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]+", name) for name in used):
        descriptor["configuration"] = {"catalogers": {"used": used}}

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent, delete=False) as stream:
        pending = Path(stream.name)
        json.dump(data, stream)
    try:
        pending.replace(output)
    finally:
        pending.unlink(missing_ok=True)
    return data, provenance


def convert(selected_path: Path, output_path: Path, settings: Settings) -> dict[str, Any]:
    source = selected_path.resolve(strict=True)
    if source.stat().st_size > settings.max_sbom_bytes:
        raise ValueError("Selected SBOM exceeds size limit")
    return _syft(["convert", str(source), "-o", "cyclonedx-json@1.6"], settings, output=output_path)

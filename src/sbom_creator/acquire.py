"""Bounded, passive acquisition of explicitly allowed build inputs."""

from __future__ import annotations

import base64
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SYFT_VERSION = "1.51.1"


@dataclass(frozen=True)
class Settings:
    bitbucket_hosts: tuple[str, ...] = ()
    registry_hosts: tuple[str, ...] = ()
    git_binary: str = "git"
    docker_binary: str = "docker"
    syft_binary: str = "syft"
    image_platform: str = "linux/amd64"
    pull_image: bool = True
    bitbucket_auth_mode: str = "bearer"
    checkout_timeout: int = 300
    scan_timeout: int = 900
    image_timeout: int = 900
    max_output_bytes: int = 4 * 1024 * 1024
    max_sbom_bytes: int = 64 * 1024 * 1024
    max_checkout_bytes: int = 2 * 1024 * 1024 * 1024
    max_archive_bytes: int = 8 * 1024 * 1024 * 1024
    max_checkout_files: int = 250_000

    def __post_init__(self) -> None:
        if self.bitbucket_auth_mode not in ("bearer", "basic"):
            raise ValueError("SBOM_BITBUCKET_AUTH_MODE must be bearer or basic")
        if not re.fullmatch(r"[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9]+)?", self.image_platform):
            raise ValueError("SBOM_IMAGE_PLATFORM must be os/architecture[/variant]")
        for key in ("checkout_timeout", "scan_timeout", "image_timeout", "max_output_bytes",
                    "max_sbom_bytes", "max_checkout_bytes", "max_archive_bytes", "max_checkout_files"):
            if getattr(self, key) <= 0:
                raise ValueError(f"{key} must be positive")

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        values: dict[str, Any] = {}
        for key in cls.__dataclass_fields__:
            raw = os.getenv(f"SBOM_{key.upper()}")
            if raw is None:
                continue
            default = getattr(defaults, key)
            if isinstance(default, tuple):
                values[key] = tuple(item.strip().lower() for item in raw.split(",") if item.strip())
            elif isinstance(default, bool):
                if raw.lower() not in ("true", "false"):
                    raise ValueError(f"SBOM_{key.upper()} must be true or false")
                values[key] = raw.lower() == "true"
            elif isinstance(default, int):
                values[key] = int(raw)
            else:
                values[key] = raw
        return cls(**values)


def secret(name: str) -> str:
    """Read service-managed credentials without returning them in errors or provenance."""
    filename = os.getenv(f"{name}_FILE")
    try:
        value = Path(filename).read_text(encoding="utf-8").strip() if filename else os.getenv(name, "")
    except OSError:
        raise ValueError(f"Cannot read configured secret {name}") from None
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"Invalid control character in {name}")
    return value


def validate_repository_url(value: str, settings: Settings) -> str:
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname
                 and parsed.netloc.lower() in {host.lower() for host in settings.bitbucket_hosts}
                 and parsed.username is None and parsed.password is None
                 and not parsed.fragment and not parsed.query and parsed.path not in ("", "/")
                 and not any(character.isspace() or ord(character) < 32 for character in value)
                 and "\\" not in value and len(value) <= 2048)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Repository requires an HTTPS URL on SBOM_BITBUCKET_HOSTS, without credentials/query/fragment")
    return value


def validate_commit(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value):
        raise ValueError("A full 40- or 64-character commit SHA is required")
    return value.lower()


def image_reference(value: str, settings: Settings) -> str:
    reference = value.removeprefix("https://")
    host, separator, path = reference.partition("/")
    if (len(value) > 2048 or not separator or not path
            or host.lower() not in {item.lower() for item in settings.registry_hosts}
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/@-]*", reference)
            or "@" in host or "://" in reference or ".." in path.split("/")):
        raise ValueError("Image registry must be configured in SBOM_REGISTRY_HOSTS")
    if "@" in path:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*(?::[\w.-]+)?@sha256:[a-f0-9]{64}", path):
            raise ValueError("Image requires a valid sha256 digest")
    elif not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[\w][\w.-]{0,127}", path):
        raise ValueError("Image requires an explicit tag or sha256 digest")
    return reference


def validate_inputs(repository_url: str, commit: str, image: str, settings: Settings) -> None:
    validate_repository_url(repository_url, settings)
    validate_commit(commit)
    image_reference(image, settings)


def clean_environment() -> dict[str, str]:
    # Pass transport/runtime settings, not unrelated model, CI, cloud or service secrets.
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE",
               "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
               "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "DOCKER_HOST", "DOCKER_TLS_VERIFY",
               "DOCKER_CERT_PATH", "DOCKER_API_VERSION"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def tree_size(path: Path, max_files: int | None = None) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = count = 0
    for directory, names, filenames in os.walk(path, followlinks=False):
        names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
        for name in filenames:
            item = Path(directory) / name
            if item.is_symlink():
                continue
            try:
                total += item.stat().st_size
            except FileNotFoundError:
                continue  # Git can rename packs while fetching.
            count += 1
            if max_files is not None and count > max_files:
                raise RuntimeError("Checkout exceeds file count limit")
    return total


def _kill(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.kill()
    process.wait(timeout=10)


def run_command(args: list[str], *, cwd: Path, env: dict[str, str], timeout: int,
                max_output_bytes: int, label: str, input_bytes: bytes | None = None,
                monitored_paths: tuple[tuple[Path, int], ...] = (),
                max_files: int | None = None) -> str:
    """No shell; bound time, diagnostic output and artifact growth. Never expose stderr."""
    with tempfile.TemporaryDirectory(prefix="sbom-process-") as temporary:
        out = Path(temporary) / "stdout"
        err = Path(temporary) / "stderr"
        incoming = Path(temporary) / "stdin"
        incoming.write_bytes(input_bytes or b"")
        process = None
        try:
            with out.open("wb") as stdout, err.open("wb") as stderr, incoming.open("rb") as stdin:
                process = subprocess.Popen(args, cwd=cwd, env=env, stdin=stdin,
                                           stdout=stdout, stderr=stderr,
                                           start_new_session=os.name != "nt")
                deadline = time.monotonic() + timeout
                while True:
                    if out.stat().st_size + err.stat().st_size > max_output_bytes:
                        raise RuntimeError(f"{label} exceeded output limit")
                    if any(tree_size(path, max_files) > limit for path, limit in monitored_paths):
                        raise RuntimeError(f"{label} exceeded artifact size limit")
                    if process.poll() is not None:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"{label} timed out")
                    time.sleep(0.05)
                if process.returncode:
                    raise RuntimeError(f"{label} failed (exit {process.returncode}); command output redacted")
            return out.read_text(encoding="utf-8", errors="replace").strip()
        except FileNotFoundError:
            raise RuntimeError(f"{label} executable is unavailable") from None
        finally:
            if process is not None:
                _kill(process)


def inspect_checkout(destination: Path, settings: Settings) -> dict[str, Any]:
    """Reject links escaping the scan root and record content intentionally not fetched."""
    root = destination.resolve()
    if tree_size(root, settings.max_checkout_files) > settings.max_checkout_bytes:
        raise RuntimeError("Checkout exceeds size limit")
    lfs_pointers: list[str] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        for name in names + filenames:
            item = Path(directory) / name
            if item.is_symlink():
                try:
                    target = item.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise ValueError("Checkout contains a dangling or cyclic symlink") from None
                if not target.is_relative_to(root):
                    raise ValueError("Checkout contains a symlink outside the repository")
        names[:] = [name for name in names if name != ".git" and not (Path(directory) / name).is_symlink()]
        for name in filenames:
            path = Path(directory) / name
            if path.is_symlink() or path.stat().st_size > 1024:
                continue
            with path.open("rb") as stream:
                if stream.read(128).startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                    lfs_pointers.append(path.relative_to(root).as_posix())
    return {"submodules_fetched": False, "gitmodules_present": (root / ".gitmodules").exists(),
            "lfs_fetched": False, "lfs_pointer_paths": sorted(lfs_pointers),
            "source_build_executed": False}


def checkout(repository_url: str, commit: str, dest: Path, settings: Settings) -> dict[str, Any]:
    validate_repository_url(repository_url, settings)
    commit = validate_commit(commit)
    dest.mkdir(parents=True, exist_ok=False)
    environment = clean_environment()
    config = {"core.hooksPath": os.devnull, "core.fsmonitor": "false",
              "http.followRedirects": "false", "http.sslVerify": "true",
              "protocol.allow": "never", "protocol.https.allow": "always",
              "credential.helper": "", "submodule.recurse": "false"}
    token = secret("SBOM_BITBUCKET_TOKEN")
    if token:
        if settings.bitbucket_auth_mode == "basic":
            username = secret("SBOM_BITBUCKET_USERNAME") or "x-bitbucket-api-token-auth"
            if ":" in username:
                raise ValueError("SBOM_BITBUCKET_USERNAME cannot contain a colon")
            encoded = base64.b64encode(f"{username}:{token}".encode()).decode()
            authorization = f"Basic {encoded}"
        else:
            authorization = f"Bearer {token}"
        config[f"http.{repository_url}.extraHeader"] = f"Authorization: {authorization}"
    ca_bundle = os.getenv("SBOM_CA_BUNDLE")
    if ca_bundle:
        config["http.sslCAInfo"] = str(Path(ca_bundle).resolve(strict=True))
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                        "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_COUNT": str(len(config))})
    for index, (key, value) in enumerate(config.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value

    def git(*args: str) -> str:
        return run_command([settings.git_binary, *args], cwd=dest, env=environment,
                           timeout=settings.checkout_timeout, max_output_bytes=settings.max_output_bytes,
                           label=f"Git {args[0]}", monitored_paths=((dest, settings.max_checkout_bytes),),
                           max_files=settings.max_checkout_files)

    # Equivalent to a clone with one exact fetched revision; never fetch branch tips first.
    git("init", "--quiet", "--template=", f"--object-format={'sha256' if len(commit) == 64 else 'sha1'}")
    git("remote", "add", "origin", repository_url)
    git("fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "origin", commit)
    git("checkout", "--detach", "--force", "FETCH_HEAD")
    resolved = git("rev-parse", "HEAD").lower()
    if resolved != commit:
        raise RuntimeError("Fetched HEAD does not match the requested commit")
    coverage = inspect_checkout(dest, settings)
    return {"repository_url": repository_url, "requested_commit": commit, "commit": resolved,
            "checkout_method": "git-init-fetch-exact-detached", "build_link": "unverified",
            "coverage": coverage}

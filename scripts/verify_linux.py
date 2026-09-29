"""Verify the installed Linux service without external network or model calls.

Run in the final image with network disabled, this file mounted read-only, and
the host's src directory mounted at /expected-src solely for hash comparison.
No expected source directory is added to Python's import path.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import secrets
import socket
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

MODULES = ("sbom_creator", "sbom_creator.acquire", "sbom_creator.scanner", "sbom_creator.core",
           "sbom_creator.llm", "sbom_creator.pipeline", "sbom_creator.service", "sbom_creator.validation",
           "sbom_creator.exporter", "sbom_creator.cli", "sbom_creator.payload")


def module_evidence(expected_root: Path, module_prefix: Path) -> dict:
    result = {}
    for name in MODULES:
        module = importlib.import_module(name)
        actual = Path(module.__file__).resolve()
        if not actual.is_relative_to(module_prefix):
            raise AssertionError(f"{name} imported outside the expected installed module prefix")
        relative = Path(*name.split("."))
        expected = expected_root / (relative / "__init__.py" if name == "sbom_creator" else relative.with_suffix(".py"))
        actual_hash = hashlib.sha256(actual.read_bytes()).hexdigest()
        expected_hash = hashlib.sha256(expected.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise AssertionError(f"Installed {name} differs from expected host source")
        result[name] = {"path": str(actual), "sha256": actual_hash,
                        "expected_path": str(expected), "expected_sha256": expected_hash}
    return result


def verify(expected_root: Path, module_prefix: Path) -> dict:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Run this verifier inside the Linux service image")
    expected_root = expected_root.resolve(strict=True)
    module_prefix = module_prefix.resolve(strict=True)
    before = module_evidence(expected_root, module_prefix)
    import uvicorn

    from sbom_creator.acquire import Settings, clean_environment, inspect_checkout
    from sbom_creator.service import create_app

    for key in list(os.environ):
        if key.startswith("SBOM_"):
            os.environ.pop(key)
    token = secrets.token_urlsafe(32)
    os.environ["SBOM_API_TOKEN"] = token
    os.environ["OPENAI_API_KEY"] = "unrelated-test-sentinel-not-a-real-key"
    if "OPENAI_API_KEY" in clean_environment():
        raise AssertionError("An unrelated service secret reaches child processes")
    with tempfile.TemporaryDirectory(prefix="sbom-linux-verifier-") as directory:
        root = Path(directory)
        repo = root / "symlink-repo"
        repo.mkdir()
        (repo / "escape").symlink_to("/etc/passwd")
        try:
            inspect_checkout(repo, Settings())
        except ValueError:
            pass
        else:
            raise AssertionError("Escaping source symlink was accepted")
        app = create_app(workspace=root / "api", settings=Settings(
            bitbucket_hosts=("bitbucket.org",), registry_hosts=("docker.io",),
            git_binary="/nonexistent/sbom-verifier-git"))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        base = "http://127.0.0.1:" + str(sock.getsockname()[1])
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()

        def request(path, method="GET", payload=None, authenticated=False):
            headers = {"Content-Type": "application/json"}
            if authenticated:
                headers["Authorization"] = "Bearer " + token
            req = urllib.request.Request(base + path, headers=headers, method=method,
                                         data=json.dumps(payload).encode() if payload is not None else None)
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())

        try:
            deadline = time.monotonic() + 10
            while not server.started:
                if time.monotonic() >= deadline:
                    raise RuntimeError("API startup timed out")
                time.sleep(0.05)
            # Default rules must reach acquisition without a model. Git is deliberately unavailable.
            valid = {"repository_url": "https://bitbucket.org/artifact_graph/python-service.git",
                     "commit": "a" * 40, "image": "docker.io/library/alpine:3.22"}
            health_code, health = request("/health")
            assert health_code == 200
            unauth_code, _ = request("/v1/analyses", "POST", valid)
            assert unauth_code == 401
            os.environ["SBOM_API_TOKEN"] = ""
            missing_token_code, _ = request("/v1/analyses", "POST", valid, True)
            assert missing_token_code == 503
            os.environ["SBOM_API_TOKEN"] = token
            os.environ["SBOM_API_TOKEN_FILE"] = str(root / "missing-token")
            unreadable_token_code, _ = request("/v1/analyses", "POST", valid, True)
            assert unreadable_token_code == 503
            oversized = root / "oversized-token"
            oversized.write_text("x" * 8193)
            os.environ["SBOM_API_TOKEN_FILE"] = str(oversized)
            oversized_token_code, _ = request("/v1/analyses", "POST", valid, True)
            assert oversized_token_code == 503
            os.environ.pop("SBOM_API_TOKEN_FILE")
            invalid_code, _ = request("/v1/analyses", "POST", {
                **valid, "repository_url": "https://untrusted.example/a.git"}, True)
            assert invalid_code == 422
            accepted_code, accepted = request("/v1/analyses", "POST", valid, True)
            assert accepted_code == 202
            deadline = time.monotonic() + 10
            while True:
                status_code, state = request(accepted["status_url"], authenticated=True)
                assert status_code == 200
                if state["status"] == "failed":
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Missing-Git job did not fail closed")
                time.sleep(0.05)
            assert state["error"] == "RuntimeError"
            assert state.get("stage") == "checkout"
            blocked_code, _ = request(accepted["status_url"] + "/artifacts/final.cdx.json", authenticated=True)
            assert blocked_code == 409
            assert not list((root / "api").rglob("final.cdx.json"))
            assert before == module_evidence(expected_root, module_prefix)
            evidence = {
                "status": "passed", "verified_at": datetime.now(UTC).isoformat(),
                "python_version": sys.version.split()[0], "module_prefix": str(module_prefix),
                "runtime_modules": before, "host_module_hashes_match": True,
                "source_unchanged_during_test": True, "health_http": health_code, "health": health,
                "unauthenticated_http": unauth_code, "unconfigured_api_token_http": missing_token_code,
                "unreadable_api_token_file_http": unreadable_token_code,
                "oversized_api_token_file_http": oversized_token_code,
                "untrusted_repository_http": invalid_code, "accepted_job_http": accepted_code,
                "missing_git_job_status": state["status"], "missing_git_error_type": state["error"],
                "missing_git_failure_stage": state.get("stage"),
                "unpublished_artifact_http": blocked_code, "final_sbom_published": False,
                "model_configured": False, "model_calls": 0, "credentials_persisted": False,
                "escaping_symlink_rejected": True, "unrelated_secret_environment_removed": True,
                "scope": "real Linux loopback HTTP and default rules reaching unavailable Git; no build or model assessment",
            }
            assert token not in json.dumps(evidence)
            return evidence
        finally:
            server.should_exit = True
            thread.join(10)
            sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-root", type=Path, default=Path("/expected-src"),
                        help="Read-only host src directory; only read for SHA256 comparison")
    parser.add_argument("--module-prefix", type=Path, default=Path(sysconfig.get_paths()["purelib"]),
                        help="Required actual import directory; defaults to installed site-packages")
    parser.add_argument("--output", type=Path, help="Optional JSON evidence path (always also prints JSON)")
    args = parser.parse_args()
    try:
        result = verify(args.expected_root, args.module_prefix)
    except Exception as error:  # noqa: BLE001 -- never publish raw secret-bearing exception text
        result = {"status": "failed", "error_type": type(error).__name__}
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

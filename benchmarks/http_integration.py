"""Real Bitbucket -> HTTPS test registry -> installed API, with no LLM.

Only a previously built test image is pushed, to a newly created loopback registry.
The test CA is trusted in a derived test service image, never installed on the host.
All owned containers are removed afterwards; evidence/registry data stay in .work.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbom_creator.pipeline import sha256, write_json
from sbom_creator.validation import validate_cyclonedx, validate_export_identity, validate_syft


def command(args, *, env=None, timeout=180):
    result = subprocess.run(args, capture_output=True, timeout=timeout, env=env, check=False)
    if result.returncode:
        # Do not publish raw command output: the service environment carries a Git token.
        raise RuntimeError(f"Test command {args[0]} {args[1]} failed with exit {result.returncode}")
    return result.stdout.decode("utf-8", errors="replace").strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(work, report, credential_file, openssl):
    if work.exists() or report.exists():
        raise FileExistsError("Choose fresh test paths")
    work.mkdir(parents=True)
    tls, build, jobs, storage = (work / name for name in ("tls", "service", "jobs", "registry"))
    for path in (tls, build, jobs, storage):
        path.mkdir()
    baseline = json.loads((ROOT / "benchmarks/results/rules-v2-20260930/results.json").read_bytes())
    row = next(r for r in baseline["repositories"] if r["id"] == "bitbucket-python-service")
    old_provenance = json.loads((Path(row["analysis_directory"]) / "provenance.json").read_bytes())
    registry_port, api_port = free_port(), free_port()
    if registry_port == api_port:
        api_port = free_port()
    command([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", str(tls / "key.pem"), "-out", str(tls / "ca.crt")])
    (build / "ca.crt").write_bytes((tls / "ca.crt").read_bytes())
    (build / "Dockerfile").write_text("FROM sbom-creator:0.3.0\nCOPY ca.crt /usr/local/share/ca-certificates/fixture.crt\nRUN update-ca-certificates\n", encoding="utf-8")
    (build / ".dockerignore").write_text("*\n!ca.crt\n!Dockerfile\n", encoding="utf-8")
    suffix = secrets.token_hex(6)
    test_image = "sbom-creator-http-fixture:" + suffix
    command(["docker", "build", "-t", test_image, str(build)])
    containers = []
    token = secrets.token_urlsafe(32)
    base = f"http://127.0.0.1:{api_port}"

    def request(path, *, payload=None, authenticated=True, raw=False):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(base + path, headers=headers,
            data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read()
                return response.status, body if raw else json.loads(body)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    try:
        registry = command(["docker", "run", "-d", "--name", "sbom-test-registry-" + suffix,
            "--label", "sbom-creator.test=" + suffix, "--memory=256m", "--cpus=1",
            "-p", f"127.0.0.1:{registry_port}:{registry_port}", "-p", f"127.0.0.1:{api_port}:8080",
            "--mount", f"type=bind,source={tls},target=/certs,readonly",
            "--mount", f"type=bind,source={storage},target=/var/lib/registry",
            "-e", f"REGISTRY_HTTP_ADDR=0.0.0.0:{registry_port}",
            "-e", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ca.crt",
            "-e", "REGISTRY_HTTP_TLS_KEY=/certs/key.pem", "registry:2.8.3"])
        containers.append(registry)
        time.sleep(2)
        target = f"localhost:{registry_port}/sbom-test/python-service:{row['commit']}"
        command(["docker", "tag", row["image_id"], target])
        command(["docker", "push", target], timeout=300)
        # Existing authorization covers reading this Bitbucket token; no admin writes.
        from inspect_bitbucket import credentials
        git = credentials(credential_file)
        env = dict(os.environ, SBOM_API_TOKEN=token, SBOM_BITBUCKET_TOKEN=git["BITBUCKET_TOKEN"])
        service = command(["docker", "run", "-d", "--name", "sbom-test-api-" + suffix,
            "--label", "sbom-creator.test=" + suffix, "--network", "container:" + registry,
            "--cpus=2", "--memory=1g", "--pids-limit=128",
            "--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
            "--mount", f"type=bind,source={jobs},target=/workspace",
            "-e", "SBOM_API_TOKEN", "-e", "SBOM_BITBUCKET_TOKEN",
            "-e", "SBOM_BITBUCKET_AUTH_MODE=basic", "-e", "SBOM_BITBUCKET_HOSTS=bitbucket.org",
            "-e", f"SBOM_REGISTRY_HOSTS=localhost:{registry_port}", test_image], env=env)
        containers.append(service)
        deadline = time.monotonic() + 30
        while True:
            try:
                if request("/health", authenticated=False)[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("Test API did not become healthy")
            time.sleep(0.2)
        payload = {"repository_url": row["repository_url"], "commit": row["commit"], "image": target}
        assert request("/v1/analyses", payload=payload, authenticated=False)[0] == 401
        started = time.monotonic()
        code, accepted = request("/v1/analyses", payload=payload)
        assert code == 202
        accepted_http = code
        samples = []
        while time.monotonic() - started < 600:
            _, state = request(accepted["status_url"])
            if state["status"] in {"failed", "succeeded"}:
                break
            samples.append(json.loads(command(["docker", "stats", service, "--no-stream", "--format", "{{json .}}"], timeout=15)))
            time.sleep(1)
        else:
            raise RuntimeError("Test analysis timed out")
        if state["status"] != "succeeded":
            write_json(work / "failed-job.json", state)
            raise RuntimeError("API job failed; sanitized job status preserved")
        elapsed = time.monotonic() - started
        downloaded = work / "downloaded"
        downloaded.mkdir()
        for name in state["artifacts"]:
            code, data = request(accepted["status_url"] + "/artifacts/" + name, raw=True)
            assert code == 200
            (downloaded / name).write_bytes(data)
        selected = json.loads((downloaded / "selected.syft.json").read_bytes())
        final = json.loads((downloaded / "final.cdx.json").read_bytes())
        provenance = json.loads((downloaded / "provenance.json").read_bytes())
        validate_syft(selected)
        validate_cyclonedx(final)
        validate_export_identity(final, selected)
        assert provenance["git"]["commit"] == row["commit"]
        assert provenance["image"]["image_config_digest"] == old_provenance["image"]["image_config_digest"]
        assert provenance["image"]["acquisition"] == "registry" and provenance["assessment"]["mode"] == "rules"
        assert provenance["image"]["container_started"] is False
        result = {"passed": True, "scope": "Actual test Bitbucket clone, local HTTPS registry pull, installed HTTP API, all artifact downloads",
            "base_service_image_id": command(["docker", "image", "inspect", "sbom-creator:0.3.0", "--format", "{{.Id}}"]),
            "service_image_id": command(["docker", "image", "inspect", test_image, "--format", "{{.Id}}"]),
            "repository_url": row["repository_url"], "commit": row["commit"], "submitted_image": target,
            "registry_digest": provenance["image"]["registry_digest"],
            "source_build_image_config_digest_matches": True,
            "unauthenticated_http": 401, "accepted_http": accepted_http,
            "status": state["status"], "summary": state["result"], "elapsed_seconds": round(elapsed, 3),
            "resource_limit": {"cpus": 2, "memory_bytes": 1073741824, "pids": 128},
            "resource_samples": [{k: s[k] for k in ("CPUPerc", "MemUsage", "MemPerc", "PIDs")} for s in samples],
            "model_calls": 0, "credentials_in_report": False, "downloaded_directory": str(downloaded),
            "artifacts_sha256": {p.name: sha256(p) for p in downloaded.iterdir()},
            "registry_tls": True, "test_ca_installed_on_host": False,
            "build_link": "unverified; test build/config correspondence checked, no production attestation"}
        assert token not in json.dumps(result) and git["BITBUCKET_TOKEN"] not in json.dumps(result)
        write_json(report, result)
        return result
    finally:
        for container in reversed(containers):
            command(["docker", "rm", "-f", container], timeout=30)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--credential-file", type=Path, required=True)
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    result = run(args.work.resolve(), args.report.resolve(), args.credential_file, args.openssl)
    print(json.dumps({k: v for k, v in result.items() if k not in {"resource_samples", "artifacts_sha256"}}, indent=2))

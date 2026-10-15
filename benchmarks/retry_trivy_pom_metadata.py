"""Retry passive POM metadata resolution only after recorded server backoff."""
import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime

from run import ROOT, atomic_json


def backoff_elapsed(policy, now):
    return now >= datetime.fromisoformat(policy['not_before_utc'])


def latest_backoff(policies):
    if not policies:
        raise ValueError('Missing explicit retry policy')
    return max(policies, key=lambda policy: datetime.fromisoformat(policy['not_before_utc']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    policies = [json.loads(path.read_bytes()) for path in (ROOT/'benchmarks/results').glob('trivy-reactor-source-optional-online-v*/retry-policy.json')]
    policy = latest_backoff(policies)
    if not backoff_elapsed(policy, datetime.now(UTC)):
        raise RuntimeError('Recorded server Retry-After has not elapsed; no network request made')
    frozen = json.loads((ROOT/'benchmarks/results/trivy-reactor-source-optional-v1/candidate-freeze.json').read_bytes())
    for name, digest in frozen['files'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen development predictor changed')
    projection = ROOT/'benchmarks/.work/paired-javalin-reactor-v1/source-optional-projection-v1'
    manifest = json.loads((ROOT/'benchmarks/results/trivy-reactor-source-optional-v1/projection.json').read_bytes())
    for item in manifest['files']:
        if hashlib.sha256((projection/item['path']).read_bytes()).hexdigest() != item['projection_sha256']:
            raise ValueError('Projection inputs changed')
    output = ROOT/args.output
    if output.exists():
        raise FileExistsError('Preserve prior attempt; choose fresh output')
    output.mkdir(parents=True)
    cache = output/'cache'
    command = [str(ROOT/'benchmarks/.work/trivy-r34/trivy.exe'), 'fs', str(projection), '--format', 'cyclonedx',
               '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--cache-dir', str(cache),
               '--output', str(output/'sbom.json')]
    environment = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
    environment.update(TEMP=str(output), TMP=str(output), HOME=str(output), USERPROFILE=str(output))
    started = time.monotonic()
    try:
        result = subprocess.run(command, env=environment, capture_output=True, timeout=180, check=False)
        code, log = result.returncode, result.stdout+result.stderr
    except subprocess.TimeoutExpired as error:
        code, log = None, (error.stdout or b'')+(error.stderr or b'')+b'\nTIMEOUT180'
    (output/'scan.log').write_bytes(log)
    atomic_json(output/'run.json', {'command': command, 'exit_code': code, 'elapsed_seconds': time.monotonic()-started,
                'backoff_checked_before_network': True, 'runtime_changed': False, 'version': '0.75.0',
                'mode': 'POM optional projection with Maven metadata network, isolated home/cache, no project execution'})
    print(json.dumps({'exit_code': code, 'tail': log[-1600:].decode(errors='replace')}))


if __name__ == '__main__':
    main()

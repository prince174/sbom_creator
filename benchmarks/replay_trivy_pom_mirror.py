"""Replay passive source POM resolution against the frozen public mirror config."""
import argparse
import hashlib
import json
import os
import subprocess
import time

from run import ROOT, atomic_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    frozen = json.loads((ROOT/'benchmarks/results/trivy-reactor-source-optional-v1/candidate-freeze.json').read_bytes())
    for name, digest in frozen['files'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen predictor changed')
    tool = ROOT/'benchmarks/.work/trivy-r34/trivy.exe'
    if hashlib.sha256(tool.read_bytes()).hexdigest() != frozen['trivy_binary_sha256']:
        raise ValueError('Trivy binary changed')
    projection = ROOT/'benchmarks/.work/paired-javalin-reactor-v1/source-optional-projection-v1'
    manifest = json.loads((ROOT/'benchmarks/results/trivy-reactor-source-optional-v1/projection.json').read_bytes())
    for item in manifest['files']:
        if hashlib.sha256((projection/item['path']).read_bytes()).hexdigest() != item['projection_sha256']:
            raise ValueError('Projection changed')
    output = ROOT/args.output
    if output.exists():
        raise FileExistsError('Preserve previous output')
    output.mkdir(parents=True)
    configuration = (ROOT/'benchmarks/results/trivy-reactor-source-optional-mirror-v1/trivy.yaml').read_bytes()
    (output/'trivy.yaml').write_bytes(configuration)
    command = [str(tool), 'fs', str(projection), '--config', str(output/'trivy.yaml'), '--format', 'cyclonedx',
               '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--cache-dir', str(output/'cache'),
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
                'mirror_config_sha256': hashlib.sha256(configuration).hexdigest(), 'runtime_changed': False,
                'version': '0.75.0', 'mode': 'Public mirror POM metadata, no origin fallback configured; empty home/cache; no project execution'})
    if code != 0:
        raise RuntimeError('Mirror scan failed; evidence preserved')


if __name__ == '__main__':
    main()

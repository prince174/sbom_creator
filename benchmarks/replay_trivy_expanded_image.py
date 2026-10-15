"""Replay frozen offline Trivy image scans without build or reference inputs."""
import argparse
import hashlib
import json
import os
import subprocess
import time

from run import ROOT, atomic_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pair', choices=('javalin-reactor', 'spring-petclinic'), required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = ROOT/args.output
    if output.exists():
        raise FileExistsError('Choose a fresh output; original evidence is immutable')
    tool = ROOT/'benchmarks/.work/trivy-r34/trivy.exe'
    cache = ROOT/'benchmarks/.work/trivy-reactor-image-v1/cache'
    frozen = json.loads((ROOT/'benchmarks/results/trivy-reactor-image-v3/run.json').read_bytes())
    with (cache/'java-db/trivy-java.db').open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != frozen['database']['sha256'] or hashlib.sha256(tool.read_bytes()).hexdigest() != frozen['binary_sha256']:
        raise ValueError('Tool or Java DB differs from frozen version')
    archive = ROOT/'benchmarks/.work'/('paired-'+args.pair+'-v1')/'image.tar'
    output.mkdir(parents=True)
    command = [str(tool), 'image', '--input', str(archive), '--format', 'cyclonedx', '--skip-db-update',
               '--skip-java-db-update', '--skip-version-check', '--offline-scan', '--cache-dir', str(cache),
               '--output', str(output/'sbom.json')]
    environment = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
    environment.update(TEMP=str(cache.parent), TMP=str(cache.parent))
    started = time.monotonic()
    result = subprocess.run(command, env=environment, capture_output=True, timeout=180, check=False)
    (output/'scan.log').write_bytes(result.stdout+result.stderr)
    atomic_json(output/'run.json', {'command': command, 'exit_code': result.returncode,
                'elapsed_seconds': time.monotonic()-started, 'version': '0.75.0', 'database_sha256': digest,
                'input_archive_sha256': hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest(),
                'runtime_changed': False, 'mode': 'passive offline image archive, no project execution'})
    if result.returncode:
        raise RuntimeError('Trivy failed; evidence preserved')


if __name__ == '__main__':
    main()

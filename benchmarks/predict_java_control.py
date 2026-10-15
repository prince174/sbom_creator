"""Fresh Java control prediction from frozen passive algorithms; no oracle read."""
import hashlib
import json
import os
import subprocess
import time

from http_integration import command
from run import ROOT, atomic_json
from trivy_optional_projection import project_pom
from trivy_pom_graph import extract


def main():
    project = next(p for p in json.loads((ROOT/'benchmarks/java-js-expanded-v1.json').read_bytes())['repositories'] if p['id'] == 'java-petclinic-rest')
    frozen = json.loads((ROOT/'benchmarks/results/trivy-reactor-source-optional-mirror-v1/candidate-freeze.json').read_bytes())
    for name, digest in frozen['files'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen predictor/config changed before control')
    work = ROOT/'benchmarks/.work/paired-petclinic-rest-v1'
    source = work/'src'
    if command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != project['commit'] or command(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('Fresh control source differs')
    if not (work/'image.tar').exists():
        raise FileNotFoundError('Wait for the existing build; do not duplicate it')
    output = ROOT/'benchmarks/results/petclinic-rest-frozen-control-v1'
    projection = work/'source-optional-projection-v1'
    if output.exists() or projection.exists():
        raise FileExistsError('Preserve previous prediction attempt')
    db_run = json.loads((ROOT/'benchmarks/results/trivy-reactor-image-v3/run.json').read_bytes())
    cache = ROOT/'benchmarks/.work/trivy-reactor-image-v1/cache'
    with (cache/'java-db/trivy-java.db').open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != db_run['database']['sha256']:
            raise ValueError('Frozen image Java DB changed')
    tool = ROOT/'benchmarks/.work/trivy-r34/trivy.exe'
    if hashlib.sha256(tool.read_bytes()).hexdigest() != db_run['binary_sha256']:
        raise ValueError('Frozen Trivy binary changed')
    trace = []
    for relative in command(['git', '-C', str(source), 'ls-files', '--', '*pom.xml']).splitlines():
        if relative.startswith('/') or '..' in relative.split('/'):
            raise ValueError('Unsafe tracked POM path')
        raw = (source/relative).read_bytes()
        data, changes = project_pom(raw)
        target = projection/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        trace.append({'path': relative, 'original_sha256': hashlib.sha256(raw).hexdigest(),
                      'projection_sha256': hashlib.sha256(data).hexdigest(), 'optional_declarations': changes})
    output.mkdir(parents=True)
    configuration = (ROOT/'benchmarks/results/trivy-reactor-source-optional-mirror-v1/trivy.yaml').read_bytes()
    (output/'trivy.yaml').write_bytes(configuration)
    atomic_json(output/'projection.json', {'source_commit': project['commit'], 'files': trace, 'oracle_read': False})
    for mode in ('image', 'source'):
        directory = output/mode
        directory.mkdir()
        args = [str(tool), 'image', '--input', str(work/'image.tar'), '--offline-scan', '--cache-dir', str(cache)] if mode == 'image' else [str(tool), 'fs', str(projection), '--config', str(output/'trivy.yaml'), '--cache-dir', str(directory/'cache')]
        args += ['--format', 'cyclonedx', '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--output', str(directory/'sbom.json')]
        environment = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
        environment.update(TEMP=str(directory), TMP=str(directory), HOME=str(directory), USERPROFILE=str(directory))
        started = time.monotonic()
        try:
            result = subprocess.run(args, env=environment, capture_output=True, timeout=180, check=False)
            code, log = result.returncode, result.stdout+result.stderr
        except subprocess.TimeoutExpired as error:
            code, log = None, (error.stdout or b'')+(error.stderr or b'')+b'\nTIMEOUT180'
        (directory/'scan.log').write_bytes(log)
        atomic_json(directory/'run.json', {'command': args, 'exit_code': code, 'elapsed_seconds': time.monotonic()-started,
                    'candidate_freeze_sha256': hashlib.sha256((ROOT/'benchmarks/results/trivy-reactor-source-optional-mirror-v1/candidate-freeze.json').read_bytes()).hexdigest(),
                    'oracle_read': False, 'runtime_changed': False})
        if mode == 'source' and code == 0:
            atomic_json(directory/'owner-predictions.json', {'owners': extract(json.loads((directory/'sbom.json').read_bytes())), 'oracle_read': False})
        print(mode, code, flush=True)


if __name__ == '__main__':
    main()

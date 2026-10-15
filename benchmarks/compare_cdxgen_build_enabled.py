"""External build-enabled cdxgen comparator; never part of service runtime."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import time
import uuid

from compare_java_js import all_components, coord, graph
from run import ROOT, atomic_json
from score_project_components import metrics

from sbom_creator.validation import validate_cyclonedx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pair', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--run-id', default='v1')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]{1,40}', args.run_id):
        raise ValueError('Invalid evidence namespace')
    if not re.fullmatch(r'paired-[a-z0-9-]+-v1', args.pair) or not re.fullmatch(r'sha256:[a-f0-9]{64}', args.image):
        raise ValueError('Explicit immutable image and pair required')
    source = ROOT / 'benchmarks/.work' / args.pair / 'src'
    reference_dir = ROOT / 'benchmarks/references' / args.pair
    receipt = json.loads((reference_dir / 'receipt.json').read_bytes())
    commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != receipt['commit'] or subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('Source commit/cleanliness mismatch')
    out = ROOT / 'benchmarks/results' / ('cdxgen-build-enabled-' + args.run_id) / args.pair
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'report.json').exists():
        raise FileExistsError('Completed comparison is immutable')
    module = '/gson' if receipt['project'] == 'java-gson' else '/slf4j-api' if receipt['project'] == 'java-slf4j' else ''
    script = ('mkdir /tmp/project && cp -R /src/. /tmp/project/ && cd /tmp/project' + module + ' && '
              'node --version && mvn --version && cdxgen --version && '
              'cdxgen -t java --no-recurse --spec-version 1.6 --fail-on-error -o /out/sbom.json .')
    container_name = 'sbom-cdxgen-r83-' + uuid.uuid4().hex[:12]
    command = ['docker', 'run', '--rm', '--name', container_name, '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--memory=3g', '--cpus=2', '--pids-limit=256',
               '--mount', 'type=bind,source=' + str(source) + ',target=/src,readonly',
               '--mount', 'type=bind,source=' + str(out) + ',target=/out',
               '--mount', 'type=volume,source=sbom-cdxgen-r83-m2,target=/root/.m2',
               '-e', 'PREFER_MAVEN_DEPS_TREE=true',
               '-e', 'MVN_ARGS=-Dscope=runtime -DskipTests -Dmaven.test.skip=true',
               '--entrypoint', 'sh', args.image, '-c', script]
    start = time.monotonic()
    try:
        run = subprocess.run(command, capture_output=True, timeout=900, check=False)
        code, output = run.returncode, run.stdout + run.stderr
    except subprocess.TimeoutExpired as error:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, check=False, timeout=30)
        code, output = None, (error.stdout or b'') + (error.stderr or b'') + b'\nTIMEOUT\n'
    (out / 'run.log').write_bytes(output.rstrip() + b'\n')
    report = {'project': receipt['project'], 'commit': commit, 'tool': 'cdxgen13.4.0',
              'mode': 'external Maven dependency:tree; runtime scope; no CycloneDX oracle input',
              'tool_image': args.image, 'command': command, 'returncode': code,
              'seconds': time.monotonic() - start, 'memory_limit_bytes': 3 * 1024**3,
              'cpu_limit': 2, 'status': 'NO_SBOM', 'runtime_changed': False}
    if (out / 'sbom.json').exists():
        actual = json.loads((out / 'sbom.json').read_bytes())
        validate_cyclonedx(actual)
        # First oracle read after prediction is complete.
        reference = json.loads((reference_dir / 'sbom.json').read_bytes())
        owner = coord(reference['metadata']['component'])
        expected = {coord(c) for c in all_components(reference) if coord(c)} - {owner}
        predicted = {coord(c) for c in all_components(actual) if coord(c)} - {owner}
        direct = graph(actual, owner)
        report.update(status='MEASURED' if code == 0 else 'PARTIAL_SBOM', components=metrics(predicted, expected),
                      direct=metrics(direct, graph(reference, owner)) if direct is not None else None,
                      missing=sorted(expected - predicted), extra=sorted(predicted - expected),
                      sbom_sha256=hashlib.sha256((out / 'sbom.json').read_bytes()).hexdigest())
    shutil.copyfile(ROOT / 'benchmarks/.work/cdxgen-build-enabled-v1/Dockerfile', out / 'Dockerfile')
    atomic_json(out / 'report.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

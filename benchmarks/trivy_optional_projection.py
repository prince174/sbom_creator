"""Experimental parser projection: include root optional declarations, no builds.

Only unprofiled direct declaration optional flags are changed in an isolated POM
copy. Transitive/component graphs of the projection are not production truth.
"""
import hashlib
import os
import subprocess
import time
import xml.etree.ElementTree as ET

from http_integration import command
from run import ROOT, atomic_json

NS = {'m': 'http://maven.apache.org/POM/4.0.0'}


def project_pom(raw):
    root = ET.fromstring(raw)
    changed = []
    for dependency in root.findall('m:dependencies/m:dependency', NS):
        optional = dependency.find('m:optional', NS)
        if optional is not None and optional.text == 'true':
            changed.append((dependency.findtext('m:groupId', namespaces=NS), dependency.findtext('m:artifactId', namespaces=NS)))
            optional.text = 'false'
    return (ET.tostring(root, encoding='utf-8', xml_declaration=True) if changed else raw), changed


def main():
    work = ROOT/'benchmarks/.work/paired-javalin-reactor-v1'
    source = work/'src'
    output = ROOT/'benchmarks/results/trivy-reactor-source-optional-v1'
    projection = work/'source-optional-projection-v1'
    if output.exists() or projection.exists():
        raise FileExistsError('Preserve existing projection experiment')
    if command(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('Dirty source')
    paths = command(['git', '-C', str(source), 'ls-files', '--', '*pom.xml']).splitlines()
    rows = []
    for relative in paths:
        if relative.startswith('/') or '..' in relative.split('/'):
            raise ValueError('Unsafe tracked POM path')
        raw = (source/relative).read_bytes()
        transformed, changes = project_pom(raw)
        destination = projection/relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(transformed)
        rows.append({'path': relative, 'original_sha256': hashlib.sha256(raw).hexdigest(),
                     'projection_sha256': hashlib.sha256(transformed).hexdigest(), 'optional_declarations': changes})
    output.mkdir(parents=True)
    atomic_json(output/'projection.json', {'source_commit': command(['git', '-C', str(source), 'rev-parse', 'HEAD']),
                'files': rows, 'kind': 'Unprofiled root direct optional=false parser projection; never execute or use its transitive graph as truth'})
    cache = ROOT/'benchmarks/.work/trivy-reactor-image-v1/cache'
    args = [str(ROOT/'benchmarks/.work/trivy-r34/trivy.exe'), 'fs', str(projection), '--format', 'cyclonedx',
            '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--offline-scan',
            '--cache-dir', str(cache), '--output', str(output/'sbom.json')]
    environment = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
    environment.update(TEMP=str(output), TMP=str(output), HOME=str(output), USERPROFILE=str(output))
    started = time.monotonic()
    result = subprocess.run(args, env=environment, capture_output=True, timeout=180, check=False)
    (output/'scan.log').write_bytes(result.stdout+result.stderr)
    atomic_json(output/'run.json', {'command': args, 'exit_code': result.returncode, 'elapsed_seconds': time.monotonic()-started,
                'runtime_changed': False, 'version': '0.75.0', 'mode': 'POM-only offline projection, isolated home, no project execution'})
    if result.returncode:
        raise RuntimeError('Trivy projection failed; evidence preserved')


if __name__ == '__main__':
    main()

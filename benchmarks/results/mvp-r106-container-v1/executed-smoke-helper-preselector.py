"""Run the installed image-only pipeline in a restricted, socket-free container.

Only a supplied image archive and the scanner's public Java DB are mounted as
read-only inputs. No repository, build reference or host credentials are mounted.
The immutable image ID and installed Python source hashes are retained.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import shutil
import subprocess
import time
from datetime import UTC, datetime

CONTAINER_PROGRAM = r'''
import hashlib, importlib.metadata, json, os, pathlib, shutil, subprocess, time
from dataclasses import replace
import sbom_creator
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze
from sbom_creator.validation import validate_cyclonedx

root = pathlib.Path('/workspace')
assert os.geteuid() == 10001
assert not pathlib.Path('/var/run/docker.sock').exists()
try:
    pathlib.Path('/root-write-probe').write_text('blocked')
except OSError:
    root_read_only = True
else:
    raise AssertionError('Container root filesystem is writable')
package = pathlib.Path(sbom_creator.__file__).parent
hashes = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(package.rglob('*')) if p.is_file()
          and '__pycache__' not in p.parts and p.suffix != '.pyc'}
tools = {name: subprocess.check_output(command, text=True).strip() for name, command in {
    'syft': ['syft', 'version', '-o', 'json'],
    'trivy': ['trivy', 'version', '--format', 'json'],
    'crane': ['crane', 'version']}.items()}
facts = {'uid': os.geteuid(), 'root_read_only': root_read_only,
         'docker_socket_present': False, 'package_path': str(package),
         'installed_source_hashes': hashes, 'tool_versions': tools,
         'python_packages': {d.metadata['Name']: d.version for d in importlib.metadata.distributions()},
         'tool_sha256': {name: hashlib.sha256(pathlib.Path(shutil.which(name)).read_bytes()).hexdigest()
                         for name in ('syft', 'trivy', 'crane')}}
(root/'environment.json').write_text(json.dumps(facts, indent=2)+'\n')
defaults = Settings.from_env()
assert defaults.trivy_cache_dir == '/workspace/trivy-cache'
assert defaults.image_temp_dir == '/workspace/image-cache'
assert defaults.java_backend == 'disabled'
settings = replace(defaults, registry_hosts=(os.environ['SMOKE_REGISTRY'],),
                   image_archive='/inputs/image.tar')
started = time.monotonic()
try:
    summary = analyze(None, None, os.environ['SMOKE_IMAGE'], root/'analysis', settings)
except Exception as error:
    (root/'smoke-result.json').write_text(json.dumps({'status': 'failed',
        'error_type': type(error).__name__, 'elapsed_seconds': time.monotonic()-started}, indent=2)+'\n')
    raise
for filename in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
    validate_cyclonedx(json.loads((root/'analysis'/filename).read_text()))
provenance = json.loads((root/'analysis/provenance.json').read_text())
assert provenance['source_kind'] == 'not-provided'
assert provenance['image']['acquisition'] == 'archive'
assert provenance['image']['java_image_status'] == 'corroborated'
assert (root/'analysis/image-identity-audit.json').is_file()
assert (root/'analysis/image-peer.cdx.json').is_file()
assert (root/'analysis/image-original.syft.json').is_file()
assert summary['final_count'] > 0
result = {'status': 'passed', 'elapsed_seconds': round(time.monotonic()-started, 3),
          'summary': summary, 'source_kind': provenance['source_kind'],
          'java_image_status': provenance['image']['java_image_status'],
          'image_config_digest': provenance['image']['image_config_digest'],
          'output_hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in sorted((root/'analysis').iterdir()) if p.is_file()}}
(root/'smoke-result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
'''


def export_artifacts(workspace, output):
    """Keep publishable reports outside the intentionally ignored workspace tree."""
    analysis = workspace/'analysis'
    if not analysis.is_dir():
        return {}
    target = output/'artifacts'
    target.mkdir()
    manifest = {}
    for item in sorted(analysis.iterdir()):
        if not item.is_file():
            continue
        compressed = item.stat().st_size >= 1024*1024
        destination = target/(item.name+'.gz' if compressed else item.name)
        if compressed:
            with (item.open('rb') as source, destination.open('wb') as raw,
                  gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as stream):
                shutil.copyfileobj(source, stream)
        else:
            shutil.copyfile(item, destination)
        manifest[item.name] = {'file': str(destination.relative_to(output)),
            'original_sha256': hashlib.sha256(item.read_bytes()).hexdigest(),
            'stored_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
            'original_bytes': item.stat().st_size, 'stored_bytes': destination.stat().st_size}
    (output/'artifact-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='sbom-creator:mvp-r105')
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--java-db', type=pathlib.Path, required=True)
    parser.add_argument('--image-reference', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    archive = args.archive.resolve(strict=True)
    database = args.java_db.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = output/'workspace'
    workspace.mkdir()
    (workspace/'trivy-cache').mkdir()
    (output/'container-program.py').write_text(CONTAINER_PROGRAM, encoding='utf-8')
    inspected = json.loads(subprocess.check_output(['docker', 'image', 'inspect', args.image]))[0]
    image_id = inspected['Id']
    name = 'sbom-mvp-smoke-'+str(time.time_ns())
    command = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--no-healthcheck',
        '--network=none', '--read-only', '--user=10001:10001', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--memory=3g', '--cpus=2', '--pids-limit=128',
        '--tmpfs=/tmp:rw,nosuid,nodev,size=512m,mode=1777',
        '--mount', f'type=bind,src={archive},dst=/inputs/image.tar,readonly',
        '--mount', f'type=bind,src={workspace},dst=/workspace',
        '--mount', f'type=bind,src={database},dst=/workspace/trivy-cache/java-db,readonly',
        '--env', 'SMOKE_REGISTRY='+args.image_reference.split('/')[0],
        '--env', 'SMOKE_IMAGE='+args.image_reference, image_id,
        'python', '-c', CONTAINER_PROGRAM]
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    with (output/'container.log').open('wb') as log:
        try:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       timeout=1200, check=False)
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'rm', '--force', name], stdout=log, stderr=subprocess.STDOUT,
                           check=False, timeout=30)
            exit_code = 124
    report = {'started_at': started_at, 'elapsed_seconds': round(time.monotonic()-started, 3),
        'exit_code': exit_code, 'image_id': image_id, 'image_created': inspected['Created'],
        'archive': str(archive), 'archive_bytes': archive.stat().st_size,
        'database_directory': str(database), 'reference': args.image_reference,
        'container_flags': command[1:command.index(image_id)],
        'container_program_sha256': hashlib.sha256(CONTAINER_PROGRAM.encode()).hexdigest(),
        'repository_mounted': False, 'reference_sbom_mounted': False,
        'docker_socket_mounted': False, 'host_credentials_mounted': False,
        'network': 'none', 'host_ports': [],
        'test_boundary': 'installed image-only pipeline; HTTP and registry transport are separate checks'}
    report['artifact_export_count'] = len(export_artifacts(workspace, output))
    (output/'run.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    if exit_code:
        print((output/'container.log').read_text(errors='replace')[-12000:])
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

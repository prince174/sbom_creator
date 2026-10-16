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
defaults = Settings.from_env()
reader_defaults_requested = os.getenv('SMOKE_READER_DEFAULTS', '').lower() == 'true'
facts['reader_defaults_requested'] = reader_defaults_requested
facts['reader_environment_values'] = {name: os.environ.get(name) for name in (
    'SBOM_JAVA_ARCHIVE_COMPONENTS', 'SBOM_JAVA_NESTED_WINDOWS')}
if reader_defaults_requested:
    assert all(value is None for value in facts['reader_environment_values'].values()), 'Reader defaults must not be overridden'
    assert defaults.java_archive_components is True, 'R110 must enable archive presence by default'
    assert defaults.java_nested_windows is False, 'The separate nested flag must remain false'
if os.getenv('SBOM_JAVA_NESTED_WINDOWS', '').lower() == 'true' and not hasattr(defaults, 'java_nested_windows'):
    raise RuntimeError('Selected image does not expose the experimental reader setting')
facts['java_nested_windows'] = getattr(defaults, 'java_nested_windows', False)
if os.getenv('SBOM_JAVA_ARCHIVE_COMPONENTS', '').lower() == 'true' and not hasattr(defaults, 'java_archive_components'):
    raise RuntimeError('Selected image does not expose the archive component setting')
facts['java_archive_components'] = getattr(defaults, 'java_archive_components', False)
(root/'environment.json').write_text(json.dumps(facts, indent=2)+'\n')
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
language = os.getenv('SMOKE_LANGUAGE', 'java')
if language == 'java':
    assert provenance['image']['java_image_status'] == 'corroborated'
    assert (root/'analysis/image-identity-audit.json').is_file()
    assert (root/'analysis/image-peer.cdx.json').is_file()
    assert (root/'analysis/image-original.syft.json').is_file()
else:
    assert language == 'javascript'
    image = json.loads((root/'analysis/image.syft.json').read_text())
    assert not any(a.get('type') == 'java-archive' for a in image['artifacts'])
    assert provenance['image'].get('java_image_status') != 'corroborated'
type_witnesses = {aid: fact for aid, fact in provenance['image'].get('payload_evidence', {}).items()
                  if fact.get('payload_kind') == 'declared_type_surface'}
if language == 'javascript':
    assert type_witnesses, 'This installed feature check needs an actual declared-type observation'
assert summary['final_count'] > 0
result = {'status': 'passed', 'elapsed_seconds': round(time.monotonic()-started, 3),
          'java_nested_windows': facts['java_nested_windows'],
          'java_archive_components': facts['java_archive_components'],
          'summary': summary, 'source_kind': provenance['source_kind'],
          'java_image_status': provenance['image'].get('java_image_status'),
          'language': language, 'declared_type_witnesses': type_witnesses,
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


def reader_environment(*, nested_windows=False, archive_components=False, reader_defaults=False):
    """Historical smoke selection stays explicit; R110 can test unmodified defaults."""
    if reader_defaults:
        if nested_windows or archive_components:
            raise ValueError('Reader-default smoke cannot also request explicit reader overrides')
        return ['--env', 'SMOKE_READER_DEFAULTS=true']
    return ['--env', 'SBOM_JAVA_NESTED_WINDOWS=' + str(nested_windows).lower(),
            '--env', 'SBOM_JAVA_ARCHIVE_COMPONENTS=' + str(archive_components).lower()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='sbom-creator:mvp-r105')
    parser.add_argument('--nested-windows', action='store_true',
                        help='Explicitly enable the experimental nested JAR reader; default is stable.')
    parser.add_argument('--archive-components', action='store_true',
                        help='Explicitly enable delivered archive components; default is stable.')
    parser.add_argument('--reader-defaults', action='store_true',
                        help='Omit both Java reader env overrides and verify the installed R110 defaults.')
    parser.add_argument('--language', choices=('java', 'javascript'), default='java',
                        help='Installed feature check; Java remains the existing default.')
    parser.add_argument('--archive', type=pathlib.Path, required=True)
    parser.add_argument('--java-db', type=pathlib.Path, required=True)
    parser.add_argument('--image-reference', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        reader_flags = reader_environment(nested_windows=args.nested_windows,
                                          archive_components=args.archive_components,
                                          reader_defaults=args.reader_defaults)
    except ValueError as error:
        parser.error(str(error))
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
        '--env', 'SMOKE_LANGUAGE='+args.language,
        '--env', 'SMOKE_IMAGE='+args.image_reference, *reader_flags, image_id,
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
        'java_nested_windows_requested': args.nested_windows,
        'java_archive_components_requested': args.archive_components,
        'reader_defaults_requested': args.reader_defaults,
        'language': args.language,
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

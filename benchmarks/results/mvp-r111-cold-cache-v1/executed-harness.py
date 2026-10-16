"""One isolated cold Java DB bootstrap followed by offline warm reuse, if successful.

No old public database, source repository or reference is mounted. The new named
volume is retained as evidence; a failed cold network job is never retried.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_JAVA_REPOSITORIES = (
    'mirror.gcr.io/aquasec/trivy-java-db:1',
    'ghcr.io/aquasecurity/trivy-java-db:1',
)
OFFICIAL_SOURCES = {
    'flags': 'https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/flag/db_flags.go',
    'repositories': 'https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/javadb/client.go',
    'download_returns_before_scan': 'https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/commands/artifact/run.go',
}
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
DOWNLOAD_SECONDS = 600
JOB_SECONDS = DOWNLOAD_SECONDS + 300

PREFLIGHT = r'''
import hashlib, json, os, pathlib, sqlite3
import sbom_creator
from sbom_creator.image_java import java_database_cache as module

root = pathlib.Path('/workspace')
assert os.geteuid() == 10001 and not pathlib.Path('/var/run/docker.sock').exists()
assert not any(root.iterdir()), 'Preflight requires a new empty native volume'
package = pathlib.Path(sbom_creator.__file__).parent
installed = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(package.rglob('*')) if p.is_file()
             and '__pycache__' not in p.parts and p.suffix != '.pyc'}
assert installed == json.loads(os.environ['R111_EXPECTED_PACKAGE_HASHES'])
work = root / 'preflight'
work.mkdir()
metadata = {'Version':1,'UpdatedAt':'2020-01-01T00:00:00Z','NextUpdate':'2099-01-01T00:00:00Z'}
def populate(cache):
    target = cache / 'java-db'
    target.mkdir(parents=True)
    connection = sqlite3.connect(target / 'trivy-java.db')
    try:
        connection.executescript("""
            CREATE TABLE artifacts(id INTEGER PRIMARY KEY,group_id TEXT,artifact_id TEXT);
            CREATE TABLE indices(artifact_id INTEGER,version TEXT,sha1 BLOB,archive_type TEXT,
              FOREIGN KEY(artifact_id) REFERENCES artifacts(id));
            CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id,group_id);
            CREATE INDEX indices_artifact_idx ON indices(artifact_id);
            CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1);
        """)
        connection.execute('INSERT INTO artifacts VALUES(1,?,?)',('org.synthetic','fixture'))
        connection.execute('INSERT INTO indices VALUES(1,?,?,?)',('0.0.0',bytes(20),'jar'))
        connection.commit()
    finally:
        connection.close()
    (target / 'metadata.json').write_text(json.dumps(metadata))
def files(path):
    return {p.relative_to(path).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob('*') if p.is_file()}
def forbidden(*args):
    raise AssertionError('Symlink or warm target must not invoke downloader')
passed = []
for location in ('cache-root','java-db','trivy-java.db','metadata.json'):
    case = work / location
    outside, cache = case / 'outside', case / 'cache'
    populate(outside)
    if location == 'cache-root':
        cache.symlink_to(outside, target_is_directory=True)
    elif location == 'java-db':
        cache.mkdir()
        (cache / 'java-db').symlink_to(outside / 'java-db', target_is_directory=True)
    else:
        populate(cache)
        item = cache / 'java-db' / location
        item.unlink()
        item.symlink_to(outside / 'java-db' / location)
    before = files(outside)
    try:
        module.ensure(cache, forbidden)
    except (ValueError,OSError,sqlite3.Error):
        pass
    else:
        raise AssertionError('Existing symlink accepted: ' + location)
    assert files(outside) == before
    assert (cache if location == 'cache-root' else cache / ('java-db' if location == 'java-db' else 'java-db/' + location)).is_symlink()
    passed.append('existing-symlink-' + location)
case = work / 'ancestor-symlink'
outside, linked_parent = case / 'outside', case / 'linked-parent'
outside.mkdir(parents=True)
linked_parent.symlink_to(outside, target_is_directory=True)
before = files(outside)
try:
    module.ensure(linked_parent / 'new-cache-child', forbidden)
except (ValueError,OSError,sqlite3.Error):
    pass
else:
    raise AssertionError('Symlink ancestor accepted')
assert files(outside) == before and not (outside / 'new-cache-child').exists()
assert linked_parent.is_symlink()
passed.append('symlink-ancestor-does-not-create-outside-child')
case = work / 'staged-symlink'
outside, cache = case / 'outside', case / 'cache'
populate(outside)
before = files(outside)
def linked(stage):
    (stage / 'java-db').symlink_to(outside / 'java-db', target_is_directory=True)
try:
    module.ensure(cache, linked)
except (ValueError,OSError,sqlite3.Error):
    pass
else:
    raise AssertionError('Staged symlink accepted')
assert files(outside) == before and not (cache / 'java-db').exists()
passed.append('staged-symlink-target-preserved')
for nonempty in (False, True):
    case = work / ('no-replace-' + str(nonempty))
    source, destination = case / 'source', case / 'destination'
    source.mkdir(parents=True)
    (source / 'candidate').write_bytes(b'synthetic incoming')
    destination.mkdir()
    if nonempty:
        (destination / 'sentinel').write_bytes(b'preserve existing')
    before, inode = files(destination), destination.stat().st_ino
    try:
        module.publish_noreplace(source, destination)
    except OSError:
        pass
    else:
        raise AssertionError('Existing directory was overwritten')
    assert files(destination) == before and destination.stat().st_ino == inode
    assert (source / 'candidate').read_bytes() == b'synthetic incoming'
    passed.append('atomic-no-replace-' + ('nonempty' if nonempty else 'empty'))
toy = work / 'toy-publication'
cold = module.ensure(toy, populate)
warm = module.ensure(toy, forbidden)
assert cold['java_database_cache_status'] == 'published' and warm['java_database_cache_status'] == 'reused'
assert cold['database_sha256'] == warm['database_sha256']
passed.append('atomic-positive-toy-cold-warm')
report = {'status':'passed','network':'none','uid':os.geteuid(),
          'installed_source_hashes':installed,'cases':passed,'skips':0,
          'synthetic_sqlite_only':True,'public_database_read_or_downloaded':False,
          'reference_accessed':False,'native_named_volume':True}
(root / 'preflight-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
'''

PROGRAM = r'''
import hashlib, json, os, pathlib, shutil, subprocess, time
from dataclasses import replace
from datetime import UTC, datetime
import sbom_creator
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze
from sbom_creator.validation import validate_cyclonedx

root = pathlib.Path('/workspace')
phase = os.environ['R111_PHASE']
assert phase in ('cold', 'warm')
assert os.geteuid() == 10001
assert not pathlib.Path('/var/run/docker.sock').exists()
assert all(not os.environ.get(name) for name in (
    'SBOM_API_TOKEN', 'SBOM_API_TOKEN_FILE', 'SBOM_REGISTRY_USERNAME', 'SBOM_REGISTRY_PASSWORD',
    'SBOM_REGISTRY_USERNAME_FILE', 'SBOM_REGISTRY_PASSWORD_FILE', 'OPENAI_API_KEY',
    'GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'))
try:
    pathlib.Path('/root-write-probe').write_text('blocked')
except OSError:
    root_read_only = True
else:
    raise AssertionError('Root filesystem is writable')

package = pathlib.Path(sbom_creator.__file__).parent
installed = {path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(package.rglob('*')) if path.is_file()
             and '__pycache__' not in path.parts and path.suffix != '.pyc'}
assert installed == json.loads(os.environ['R111_EXPECTED_PACKAGE_HASHES']), 'Installed package differs before network access'
defaults = Settings.from_env()
assert defaults.java_archive_components is True and defaults.java_nested_windows is False
assert defaults.java_backend == 'disabled'
assert defaults.java_db_timeout == 600
assert defaults.trivy_cache_dir == '/workspace/trivy-cache'
assert defaults.image_temp_dir == '/workspace/image-cache'
assert 'SBOM_JAVA_ARCHIVE_COMPONENTS' not in os.environ
assert 'SBOM_JAVA_NESTED_WINDOWS' not in os.environ
cache = pathlib.Path(defaults.trivy_cache_dir)
database = cache / 'java-db/trivy-java.db'
metadata = cache / 'java-db/metadata.json'
if phase == 'cold':
    assert {p.name for p in root.iterdir()} == {'preflight', 'preflight-result.json'}, 'Only sealed synthetic preflight may precede cold cache'
    assert not cache.exists(), 'No old cache may be present'
else:
    assert database.is_file() and metadata.is_file(), 'Warm mode needs only the newly acquired cache'
cache.mkdir(parents=True, exist_ok=True)
tool_hashes = {name: hashlib.sha256(pathlib.Path(shutil.which(name)).read_bytes()).hexdigest()
               for name in ('syft', 'trivy', 'crane')}
tool_versions = {name: subprocess.check_output(command, text=True).strip() for name, command in {
    'syft': ['syft', 'version', '-o', 'json'], 'trivy': ['trivy', 'version', '--format', 'json'],
    'crane': ['crane', 'version']}.items()}
facts = {'phase': phase, 'frozen_before_pipeline_at': datetime.now(UTC).isoformat(),
    'uid': os.geteuid(), 'root_read_only': root_read_only, 'docker_socket_present': False,
    'installed_source_hashes': installed, 'tool_sha256': tool_hashes, 'tool_versions': tool_versions,
    'java_archive_components_default': defaults.java_archive_components,
    'java_nested_windows_default': defaults.java_nested_windows,
    'java_db_timeout': defaults.java_db_timeout,
    'cache_database_present_before_pipeline': database.is_file(),
    'cache_metadata_present_before_pipeline': metadata.is_file(),
    'reader_environment_overrides_absent': True, 'old_database_mount_present': False,
    'cache_root': str(cache), 'metadata_before': (json.loads(metadata.read_bytes()) if metadata.is_file() else None)}
(root / (phase + '-environment.json')).write_text(json.dumps(facts, indent=2) + '\n')

settings = replace(defaults, registry_hosts=(os.environ['R111_IMAGE_REFERENCE'].split('/')[0],),
                   image_archive='/inputs/image.tar')
started = time.monotonic()
result = {'phase': phase, 'reference_accessed': False, 'source_input': False}
try:
    summary = analyze(None, None, os.environ['R111_IMAGE_REFERENCE'], root / ('analysis-' + phase), settings)
    analysis = root / ('analysis-' + phase)
    for name in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
        validate_cyclonedx(json.loads((analysis / name).read_bytes()))
    provenance = json.loads((analysis / 'provenance.json').read_bytes())
    assert provenance['source_kind'] == 'not-provided'
    assert provenance['image']['image_config_digest'] == os.environ['R111_EXPECTED_IMAGE_CONFIG']
    assert provenance['image']['java_image_status'] == 'corroborated'
    assert summary['policy_version'] == 'image-delivered-archive-v7'
    assert summary['final_count'] > 0
    engine = provenance['image']['java_identity_engine']
    expected_status = 'published' if phase == 'cold' else 'reused'
    assert engine['java_database_cache_status'] == expected_status, 'Unexpected cold/warm acquisition state'
    assert database.is_file() and metadata.is_file()
    with database.open('rb') as stream:
        observed_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert engine['database_sha256'] == observed_hash
    assert not (cache / 'db/trivy.db').exists(), 'A vulnerability DB was unexpectedly downloaded'
    assert not (cache / 'db/metadata.json').exists(), 'Vulnerability DB metadata must be absent'
    result.update(status='passed', summary=summary, image_config_digest=provenance['image']['image_config_digest'],
        java_identity_engine=engine, database_sha256=observed_hash, database_bytes=database.stat().st_size,
        metadata=json.loads(metadata.read_bytes()), metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),
        vulnerability_database_absent=True, license_or_project_execution_requested=False,
        source_kind=provenance['source_kind'],
        output_hashes={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted(analysis.iterdir()) if path.is_file()})
except Exception as error:
    result.update(status='failed', error_type=type(error).__name__)
    raise
finally:
    result['pipeline_seconds'] = round(time.monotonic() - started, 3)
    result['database_exists_after_pipeline'] = database.is_file()
    cache_files = []
    for path in cache.rglob('*'):
        if path.is_file() and not path.is_symlink():
            assert len(cache_files) < 10000, 'Cache evidence entry budget exceeded'
            cache_files.append({'path': path.relative_to(cache).as_posix(), 'bytes': path.stat().st_size})
    result['cache_files_after_pipeline'] = sorted(cache_files, key=lambda item: item['path'])
    (root / (phase + '-result.json')).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
'''


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, document):
    Path(path).write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')


def host_environment():
    allowed = {'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE',
               'TEMP', 'TMP', 'TMPDIR', 'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS',
               'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'LANG', 'LC_ALL'}
    return {name: value for name, value in os.environ.items() if name.upper() in allowed}


def container_command(image, archive, volume, phase, reference, config, hashes, name):
    if not IMAGE_ID.fullmatch(image) or phase not in ('cold', 'warm'):
        raise ValueError('Pinned image ID and one cold/warm phase are required')
    return ['docker', 'run', '--name', name, '--pull=never', '--no-healthcheck',
        '--network=' + ('bridge' if phase == 'cold' else 'none'), '--read-only',
        '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--memory=3g', '--cpus=2', '--pids-limit=128',
        '--tmpfs=/tmp:rw,nosuid,nodev,size=512m,mode=1777',
        '--mount', f'type=bind,src={archive},dst=/inputs/image.tar,readonly',
        '--mount', f'type=volume,src={volume},dst=/workspace',
        '--env', 'R111_PHASE=' + phase, '--env', 'R111_IMAGE_REFERENCE=' + reference,
        '--env', 'R111_EXPECTED_IMAGE_CONFIG=' + config,
        '--env', 'R111_EXPECTED_PACKAGE_HASHES=' + json.dumps(hashes, sort_keys=True, separators=(',', ':')),
        '--entrypoint=python', image, '-c', PROGRAM]


def preflight_command(image, archive, volume, reference, config, hashes, name):
    args = container_command(image, archive, volume, 'warm', reference, config, hashes, name)
    args[args.index('R111_PHASE=warm')] = 'R111_PHASE=preflight'
    args[-1] = PREFLIGHT
    return args


def coordinates(document):
    return Counter(json.dumps([item.get(key) for key in ('type', 'group', 'name', 'version', 'purl')],
                              separators=(',', ':')) for item in document.get('components', []))


def copy_from(container, source, target, environment):
    copied = subprocess.run(['docker', 'cp', container + ':' + source, str(target)],
                            env=environment, capture_output=True, check=False, timeout=60)
    return copied.returncode == 0


def export_analysis(folder):
    source = folder / 'analysis'
    if not source.is_dir():
        return {}
    artifacts = folder / 'artifacts'
    artifacts.mkdir()
    result = {}
    for path in sorted(source.iterdir()):
        if not path.is_file():
            continue
        destination = artifacts / (path.name + '.gz')
        with (path.open('rb') as incoming, destination.open('wb') as output,
              gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as stream):
            while block := incoming.read(1024 * 1024):
                stream.write(block)
        result[path.name] = {'file': destination.relative_to(folder).as_posix(),
                            'original_sha256': sha(path), 'original_bytes': path.stat().st_size,
                            'stored_sha256': sha(destination), 'stored_bytes': destination.stat().st_size}
    write(folder / 'artifact-manifest.json', result)
    return result


def verify_exports(folder, artifacts):
    """Independently read compressed exports; never substitute missing outputs."""
    checked = {}
    for name, item in artifacts.items():
        path = folder / item['file']
        digest = hashlib.sha256()
        size = 0
        with gzip.open(path, 'rb') as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
                size += len(block)
        checked[name] = (sha(path) == item['stored_sha256'] and size == item['original_bytes']
                         and digest.hexdigest() == item['original_sha256'])
    return checked


def inspected_container(name, environment):
    inspected = subprocess.run(['docker', 'container', 'inspect', name], env=environment,
                               capture_output=True, check=False, timeout=30)
    if inspected.returncode:
        return {'available': False, 'inspect_exit_code': inspected.returncode}
    item = json.loads(inspected.stdout)[0]
    host, configuration = item['HostConfig'], item['Config']
    return {'available': True, 'image_id': item['Image'], 'user': configuration['User'],
            'network_mode': host['NetworkMode'], 'read_only_rootfs': host['ReadonlyRootfs'],
            'cap_drop': host['CapDrop'], 'security_opt': host['SecurityOpt'],
            'memory_bytes': host['Memory'], 'nano_cpus': host['NanoCpus'],
            'mounts': [{key: mount.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'RW')}
                       for mount in item['Mounts']], 'state': item['State']['Status']}


def run_phase(output, image, archive, volume, phase, invocation, hashes, environment):
    folder = output / phase
    folder.mkdir()
    name = 'sbom-r111-' + phase + '-' + str(time.time_ns())
    command = container_command(image, archive, volume, phase, invocation['image'],
                                invocation['previously_observed_config_digest'], hashes, name)
    started = time.monotonic()
    with (folder / 'container.log').open('wb') as log:
        try:
            completed = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                       check=False, timeout=JOB_SECONDS)
            code = completed.returncode
        except subprocess.TimeoutExpired:
            # Keep the stopped container until partial evidence has been exported.
            subprocess.run(['docker', 'kill', name], env=environment, stdout=log,
                           stderr=subprocess.STDOUT, check=False, timeout=30)
            code = 124
    container_seconds = round(time.monotonic() - started, 3)
    inspected = inspected_container(name, environment)
    write(folder / 'container-inspect.json', inspected)
    copied = {}
    for source, target in ((f'/workspace/{phase}-environment.json', folder / 'environment.json'),
                           (f'/workspace/{phase}-result.json', folder / 'result.json'),
                           (f'/workspace/analysis-{phase}', folder / 'analysis')):
        copied[source] = copy_from(name, source, target, environment)
    subprocess.run(['docker', 'rm', name], env=environment, capture_output=True, check=False, timeout=30)
    exported = export_analysis(folder)
    export_verification = verify_exports(folder, exported)
    result = json.loads((folder / 'result.json').read_bytes()) if (folder / 'result.json').is_file() else None
    report = {'exit_code': code, 'container_seconds': container_seconds,
              'export_seconds': round(time.monotonic() - started - container_seconds, 3),
              'phase': phase, 'network': 'bridge' if phase == 'cold' else 'none',
              'container_flags': command[1:command.index(image)], 'image_id': image,
              'fresh_public_download_attempt_permitted': phase == 'cold',
              'download_timeout_seconds': DOWNLOAD_SECONDS, 'job_timeout_seconds': JOB_SECONDS,
              'export_success': copied, 'exported_artifact_count': len(exported),
              'compressed_exports_verified': export_verification,
              'result': result, 'reference_accessed': False,
              'status': 'passed' if code == 0 and result and result.get('status') == 'passed'
                        and all(copied.values()) and exported and all(export_verification.values()) else 'failed'}
    write(folder / 'run.json', report)
    return report


def run_preflight(output, image, archive, volume, invocation, hashes, environment):
    folder = output / 'native-preflight'
    folder.mkdir()
    name = 'sbom-r111-native-' + str(time.time_ns())
    args = preflight_command(image, archive, volume, invocation['image'],
        invocation['previously_observed_config_digest'], hashes, name)
    started = time.monotonic()
    with (folder / 'container.log').open('wb') as log:
        try:
            done = subprocess.run(args, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                  check=False, timeout=120)
            code = done.returncode
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'kill', name], env=environment, stdout=log,
                           stderr=subprocess.STDOUT, check=False, timeout=30)
            code = 124
    inspected = inspected_container(name, environment)
    copied = copy_from(name, '/workspace/preflight-result.json', folder / 'result.json', environment)
    subprocess.run(['docker', 'rm', name], env=environment, capture_output=True, check=False, timeout=30)
    result = json.loads((folder / 'result.json').read_bytes()) if copied else None
    report = {'exit_code': code, 'seconds': round(time.monotonic() - started, 3),
        'container_flags': args[1:args.index(image)], 'container_inspect': inspected, 'result': result,
        'network_jobs_started': 0, 'status': 'passed' if code == 0 and result
            and result.get('status') == 'passed' and result.get('skips') == 0
            and len(result.get('cases', [])) == 9 else 'failed'}
    write(folder / 'run.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument('--image', help='Already rebuilt exact sha256 image ID; no pull is performed.')
    candidate.add_argument('--build', action='store_true', help='One explicitly authorized local mvp-r111 build.')
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/results/mvp-r111-cold-cache-v1')
    args = parser.parse_args()
    if args.image and not IMAGE_ID.fullmatch(args.image):
        raise ValueError('Only a pinned Docker image ID is accepted')
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError('Never retry or overwrite a previous cold-network attempt')
    invocation_path = ROOT / 'benchmarks/results/mvp-r110-held-controls-v1/dbcp/invocation.json'
    invocation = json.loads(invocation_path.read_bytes())
    archive = (ROOT / invocation['archive']).resolve()
    if (archive != (ROOT / 'benchmarks/.work/paired-commons-dbcp-v1/image.tar').resolve()
            or sha(archive) != invocation['archive_sha256'] or invocation['oracle_read'] is not False):
        raise ValueError('Existing observed DBCP input binding differs')
    source = ROOT / 'src/sbom_creator'
    hashes = {path.relative_to(source).as_posix(): sha(path) for path in sorted(source.rglob('*'))
              if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    environment = host_environment()
    output.mkdir(parents=True)
    (output / 'executed-harness.py').write_bytes(Path(__file__).read_bytes())
    (output / 'container-program.py').write_text(PROGRAM, encoding='utf-8')
    (output / 'native-preflight-program.py').write_text(PREFLIGHT, encoding='utf-8')
    snapshot = output / 'executed-source/sbom_creator'
    for name in hashes:
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / name).read_bytes())
    volume = 'sbom-r111-public-java-' + str(time.time_ns())
    freeze = {'frozen_at': datetime.now(UTC).isoformat(), 'reference_accessed': False,
        'requested_image_id': args.image, 'build_requested': args.build,
        'installed_expected_source_hashes': hashes,
        'source_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in (
            ROOT / 'Dockerfile', ROOT / '.dockerignore', ROOT / 'pyproject.toml')},
        'input': {key: invocation[key] for key in ('archive', 'archive_sha256', 'image',
                   'previously_observed_config_digest')}, 'observed_input_invocation_sha256': sha(invocation_path),
        'harness_sha256': sha(Path(__file__)), 'container_program_sha256': hashlib.sha256(PROGRAM.encode()).hexdigest(),
        'preflight_program_sha256': hashlib.sha256(PREFLIGHT.encode()).hexdigest(),
        'new_workspace_volume': volume, 'old_public_database_read_or_mounted': False,
        'network_job_limit': 1, 'download_timeout_seconds': DOWNLOAD_SECONDS,
        'host_environment_names': sorted(environment), 'official_sources': OFFICIAL_SOURCES,
        'trivy_v075_default_public_repositories': list(PUBLIC_JAVA_REPOSITORIES),
        'public_repository_tags_are_mutable': True, 'publisher_authenticity_claimed': False}
    write(output / 'candidate-freeze.json', freeze)
    if args.build:
        started = time.monotonic()
        command = ['docker', 'build', '--progress=plain', '--tag', 'sbom-creator:mvp-r111', '.']
        with (output / 'build.log').open('wb') as log:
            built = subprocess.run(command, cwd=ROOT, env=environment, stdout=log,
                stderr=subprocess.STDOUT, check=False, timeout=900)
        unchanged = all(sha(source / name) == expected for name, expected in hashes.items())
        unchanged = unchanged and all(sha(ROOT / name) == expected for name, expected in freeze['source_sha256'].items())
        build = {'exit_code': built.returncode, 'seconds': round(time.monotonic() - started, 3),
                 'command': command, 'source_and_build_files_unchanged': unchanged}
        write(output / 'build.json', build)
        if built.returncode or not unchanged:
            return built.returncode or 2
        inspected_image = json.loads(subprocess.check_output(
            ['docker', 'image', 'inspect', 'sbom-creator:mvp-r111'], env=environment))[0]
        image_id = inspected_image['Id']
    else:
        inspected_image = json.loads(subprocess.check_output(
            ['docker', 'image', 'inspect', args.image], env=environment))[0]
        image_id = inspected_image['Id']
        if image_id != args.image:
            raise ValueError('Docker image identity changed')
    if not IMAGE_ID.fullmatch(image_id):
        raise ValueError('Build did not produce a pinned image ID')
    image_env = {entry.split('=', 1)[0] for entry in inspected_image['Config'].get('Env', [])}
    if image_env & {'SBOM_JAVA_ARCHIVE_COMPONENTS', 'SBOM_JAVA_NESTED_WINDOWS'}:
        raise ValueError('Image ENV must not impersonate service reader defaults')
    write(output / 'built-image.json', {'image_id': image_id, 'created': inspected_image.get('Created'),
        'config': inspected_image['Config'], 'source_file_count': len(hashes)})
    created = subprocess.run(['docker', 'volume', 'create', '--label', 'sbom-stage=r111-cold-public-db', volume],
                             env=environment, capture_output=True, text=True, check=False, timeout=30)
    write(output / 'volume.json', {'name': volume, 'create_exit_code': created.returncode,
                                  'retained_for_reproduction': True, 'old_database_volume': False})
    if created.returncode != 0:
        return created.returncode
    preflight = run_preflight(output, image_id, archive, volume, invocation, hashes, environment)
    if preflight['status'] != 'passed':
        write(output / 'report.json', {'status': 'failed-native-preflight', 'preflight': preflight,
            'network_jobs_started': 0, 'network_retry_performed': False,
            'new_public_db_volume_retained': volume})
        return 2
    cold = run_phase(output, image_id, archive, volume, 'cold', invocation, hashes, environment)
    report = {'cold': cold, 'warm': None, 'reference_accessed': False,
              'preflight': preflight, 'image_id': image_id,
              'network_jobs_started': 1, 'network_retry_performed': False,
              'new_public_db_volume_retained': volume, 'original_source_unchanged': all(
                  sha(source / name) == expected for name, expected in hashes.items()),
              'accuracy': 'not evaluated; this tests cache bootstrap and installed pipeline only'}
    if cold['status'] == 'passed':
        warm = run_phase(output, image_id, archive, volume, 'warm', invocation, hashes, environment)
        report['warm'] = warm
        if warm['status'] == 'passed':
            comparisons = {}
            for view in ('final', 'os', 'full'):
                left = json.loads((output / 'cold/analysis' / (view + '.cdx.json')).read_bytes())
                right = json.loads((output / 'warm/analysis' / (view + '.cdx.json')).read_bytes())
                comparisons[view] = coordinates(left) == coordinates(right)
            report['cold_warm_coordinate_multisets_equal'] = comparisons
            report['database_hash_equal_cold_warm'] = cold['result']['database_sha256'] == warm['result']['database_sha256']
            report['database_metadata_hash_equal_cold_warm'] = cold['result']['metadata_sha256'] == warm['result']['metadata_sha256']
    report['status'] = ('passed' if cold['status'] == 'passed' and report['warm']
                        and report['warm']['status'] == 'passed'
                        and all(report.get('cold_warm_coordinate_multisets_equal', {}).values())
                        and report.get('database_hash_equal_cold_warm') is True
                        and report.get('database_metadata_hash_equal_cold_warm') is True
                        and report['original_source_unchanged'] else 'failed')
    write(output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'cold_status': cold['status'],
                      'warm_status': report['warm']['status'] if report['warm'] else None,
                      'public_db_volume': volume}))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())


import hashlib, json, os, pathlib, shutil, subprocess, time
from dataclasses import replace
from datetime import UTC, datetime
import sbom_creator
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze
from sbom_creator.validation import validate_cyclonedx

root = pathlib.Path(os.environ['R112_RUN_DIRECTORY'])
root.mkdir()
phase = os.environ['R112_PHASE']
assert phase == 'warm'
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
assert installed == json.loads(os.environ['R112_EXPECTED_PACKAGE_HASHES']), 'Installed package differs before network access'
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

from sbom_creator.image_java import runtime
with database.open('rb') as stream:
    database_before_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
metadata_before_sha256 = hashlib.sha256(metadata.read_bytes()).hexdigest()
assert database_before_sha256 == os.environ['R112_DB_SHA256']
assert metadata_before_sha256 == os.environ['R112_METADATA_SHA256']
original_ensure = runtime.ensure_database
download_attempts = []
def no_download(_stage):
    download_attempts.append('forbidden')
    raise AssertionError('Warm installed check forbids the downloader callback')
def warm_ensure(cache, _downloader):
    return original_ensure(cache, no_download)
runtime.ensure_database = warm_ensure
original_command = runtime.run_command
def guarded_command(args, **kwargs):
    if '--download-java-db-only' in args:
        raise AssertionError('Warm installed check forbids database downloads')
    if args[1] != 'version':
        assert args[1] == 'image'
        assert all(flag in args for flag in ('--input','--offline-scan','--skip-db-update',
                                            '--skip-java-db-update','--skip-version-check'))
    return original_command(args, **kwargs)
runtime.run_command = guarded_command

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
facts.update(database_sha256_before_pipeline=database_before_sha256, metadata_sha256_before_pipeline=metadata_before_sha256, executed_program_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())
(root / (phase + '-environment.json')).write_text(json.dumps(facts, indent=2) + '\n')

settings = replace(defaults, registry_hosts=(os.environ['R112_IMAGE_REFERENCE'].split('/')[0],),
                   image_archive='/inputs/image.tar')
started = time.monotonic()
result = {'phase': phase, 'reference_accessed': False, 'source_input': False}
try:
    summary = analyze(None, None, os.environ['R112_IMAGE_REFERENCE'], root / ('analysis-' + phase), settings)
    analysis = root / ('analysis-' + phase)
    for name in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
        validate_cyclonedx(json.loads((analysis / name).read_bytes()))
    provenance = json.loads((analysis / 'provenance.json').read_bytes())
    assert provenance['source_kind'] == 'not-provided'
    assert provenance['image']['image_config_digest'] == os.environ['R112_EXPECTED_IMAGE_CONFIG']
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
    assert observed_hash == os.environ['R112_DB_SHA256']
    assert engine['java_database_download_seconds'] == 0
    assert not download_attempts
    assert hashlib.sha256(metadata.read_bytes()).hexdigest() == os.environ['R112_METADATA_SHA256']
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

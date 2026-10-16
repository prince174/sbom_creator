"""Image-only Java identity + physical evidence, without source/build inputs."""
import base64
import json
import os
import tempfile
import threading
from pathlib import Path

from .. import payload
from ..acquire import clean_environment, run_command, secret
from ..validation import validate_cyclonedx
from .archive_component_evidence import JarFiles as ArchiveJarFiles
from .archive_component_identity import POLICY as ARCHIVE_POLICY
from .archive_component_identity import bind as bind_archives
from .directory_jar_evidence import JarFiles as StoredJarFiles
from .explicit_identity_gate import prepare
from .java_database_cache import DatabaseCacheError
from .java_database_cache import _prepare_cache as prepare_cache
from .java_database_cache import ensure as ensure_database
from .public_hash_identity import PublicJavaHashLookup, file_sha256
from .seekable_jar_evidence import JarFiles
from .trivy_only_payload import supplement

DB_LOCK = threading.Lock()
VERSION = '0.75.0'


def file_sha(path):
    if not path.is_file() or path.stat().st_size > 2*1024**3:
        raise ValueError('Java database byte budget')
    return file_sha256(path)


def peer(archive, settings, temporary):
    root = Path(temporary)
    configured = Path(settings.trivy_cache_dir) if settings.trivy_cache_dir else Path.home()/'.cache/sbom-trivy'
    # Use one lexical absolute path for validation and subprocesses with a
    # different cwd. Check ancestors before creating any cache child or tool run.
    cache = Path(os.path.abspath(configured))
    try:
        prepare_cache(cache)
    except (OSError, ValueError):
        raise DatabaseCacheError('CACHE_INVALID') from None
    env = clean_environment()
    env.update(HOME=str(root), USERPROFILE=str(root), DOCKER_CONFIG=str(root),
               XDG_CONFIG_HOME=str(root), XDG_CACHE_HOME=str(root), TMP=str(root), TEMP=str(root), TMPDIR=str(root))
    config = root/'trivy-image.yaml'
    config.write_text('{}\n', encoding='utf-8')
    version = json.loads(run_command([settings.trivy_binary, 'version', '--format', 'json'],
        cwd=root, env=env, timeout=30, max_output_bytes=4096, label='Trivy image version'))
    if version.get('Version') != VERSION:
        raise ValueError('Pinned Trivy image version required')
    database = cache/'java-db/trivy-java.db'
    # Only the scanner's public distribution populates this cache. An incomplete
    # download cannot become visible as a usable shared database directory.
    with DB_LOCK:
        def download(staging):
            run_command([settings.trivy_binary, 'image', '--config', str(config), '--cache-dir', str(staging),
                '--download-java-db-only', '--skip-version-check', '--no-progress',
                '--timeout', str(settings.java_db_timeout) + 's'], cwd=root, env=env,
                timeout=settings.java_db_timeout, max_output_bytes=settings.max_output_bytes,
                monitored_paths=((staging, 2*1024**3),), max_files=10_000, label='Java identity database')
        cache_facts = ensure_database(cache, download)
        db_hash = cache_facts['database_sha256']
    raw = run_command([settings.trivy_binary, 'image', '--config', str(config), '--input', str(archive),
        '--cache-dir', str(cache), '--format', 'cyclonedx', '--offline-scan', '--skip-db-update',
        '--skip-java-db-update', '--skip-version-check'], cwd=root, env=env, timeout=settings.image_timeout,
        max_output_bytes=settings.max_sbom_bytes, monitored_paths=((root, settings.max_archive_bytes),),
        max_files=settings.max_checkout_files, label='Trivy image inventory')
    if file_sha(database) != db_hash:
        raise ValueError('Java database changed during image prediction')
    document = json.loads(raw)
    validate_cyclonedx(document, versions=('1.6', '1.7'))
    return document, {'version': VERSION, **cache_facts}


def acquire(immutable_reference, destination, settings, temporary):
    """Pull one immutable platform into an internal archive; never start it."""
    root = Path(temporary)
    credentials = root/'registry-credentials'
    credentials.mkdir()
    env = clean_environment()
    env.update(HOME=str(credentials), USERPROFILE=str(credentials), DOCKER_CONFIG=str(credentials))
    username, password = secret('SBOM_REGISTRY_USERNAME'), secret('SBOM_REGISTRY_PASSWORD')
    if bool(username) != bool(password):
        raise ValueError('Registry credentials must be paired')
    if username:
        auth = base64.b64encode((username+':'+password).encode()).decode()
        (credentials/'config.json').write_text(json.dumps({'auths': {
            immutable_reference.split('/')[0]: {'auth': auth}}}), encoding='utf-8')
        if os.name != 'nt':
            (credentials/'config.json').chmod(0o600)
    version = run_command([settings.crane_binary, 'version'], cwd=root, env=env, timeout=30,
                          max_output_bytes=4096, label='Crane version').strip()
    # Official v0.22.1 image reports its exact release-tag commit, while the
    # checksum-verified release binary reports semver. No arbitrary commit allowed.
    if version.removeprefix('v') not in ('0.22.1', '8a72a424fdecb4caa14f2d525e5d2503331442b5'):
        raise ValueError('Pinned crane version required')
    run_command([settings.crane_binary, 'pull', immutable_reference, str(destination), '--format=tarball',
        '--platform='+settings.image_platform], cwd=root, env=env, timeout=settings.image_timeout,
        max_output_bytes=settings.max_output_bytes, monitored_paths=((root, settings.max_archive_bytes),),
        max_files=settings.max_checkout_files, label='Immutable image acquisition')


def corroborate(image, archive, peer_document, *, temporary=None, nested_windows=False,
                archive_components=False, java_database=None, database_sha256=None):
    """One resource budget shared by Syft and Trivy-only physical witnesses."""
    reader = ArchiveJarFiles if archive_components else StoredJarFiles if nested_windows else JarFiles
    files = reader(archive, image, temporary=temporary)
    lookup = None
    try:
        observed = payload.collect(image, archive, files_factory=lambda *args: files,
                                   java_witness=lambda artifact, reader: reader.witness(artifact), close_files=False)
        adapted, _, audit = supplement(image, peer_document, observed, archive, files=files)
        archive_facts = {}
        if archive_components:
            if java_database is not None:
                lookup = PublicJavaHashLookup(java_database, database_sha256)
            adapted, archive_facts, archive_audit = bind_archives(image, adapted, peer_document,
                observed, files, lookup=lookup)
            audit['archive_components'] = archive_audit
            if lookup is not None:
                lookup.verify_unchanged()
                audit['archive_identity_database'] = {'sha256': lookup.sha256,
                    'lookup': 'exact full SHA1 association; not an independent Trivy identity source',
                    'publisher_authenticated': False, 'globally_unique_gav_proven': False}
        physical, envelope = prepare(adapted, audit)
        # Non-Java evidence must not change when enabling Java corroboration.
        for artifact in image['artifacts']:
            if artifact.get('foundBy') != 'java-archive-cataloger' and artifact['id'] in observed:
                physical[artifact['id']] = observed[artifact['id']]
        from ..core import checksum
        envelope['payload_sha256'] = checksum(physical)
        if archive_components:
            envelope['reader_policy'] = ARCHIVE_POLICY
            envelope['archive_presence'] = archive_facts
            envelope['archive_presence_sha256'] = checksum(archive_facts)
            envelope['archive_database_sha256'] = lookup.sha256 if lookup is not None else None
        elif nested_windows:
            envelope['reader_policy'] = 'stored-nested-directory-lru-v1'
        return adapted, physical, envelope, {'binding': audit, 'jar_resources': files.stats,
                                             'layer_resources': files.layers_reader.stats}
    finally:
        if lookup is not None:
            lookup.close()
        files.close()


def analyze(image, provenance, settings):
    parent = Path(settings.image_temp_dir) if settings.image_temp_dir else None
    if parent:
        parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sbom-image-java-', dir=parent) as temporary:
        root = Path(temporary)
        archive = Path(settings.image_archive) if settings.image_archive else root/'image.tar'
        if not settings.image_archive:
            acquire(provenance['immutable_reference'], archive, settings, root)
        peer_document, tool = peer(archive, settings, root)
        adapted, physical, envelope, audit = corroborate(image, archive, peer_document, temporary=root,
            nested_windows=settings.java_nested_windows, archive_components=settings.java_archive_components,
            java_database=((Path(settings.trivy_cache_dir) if settings.trivy_cache_dir
                            else Path.home()/'.cache/sbom-trivy')/'java-db/trivy-java.db'
                           if settings.java_archive_components else None),
            database_sha256=tool['database_sha256'])
        return adapted, {'payload_evidence': physical, 'identity_binding_envelope': envelope,
            'java_reader_policy': (ARCHIVE_POLICY if settings.java_archive_components else
                'stored-nested-directory-lru-conservative-ledger-v1' if settings.java_nested_windows
                else 'seekable-content-verification-v4'),
            'java_identity_engine': tool, 'java_image_status': 'corroborated',
            '_artifacts': {'image-original.syft.json': image, 'image-peer.cdx.json': peer_document,
                           'image-identity-audit.json': audit}}

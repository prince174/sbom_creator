"""Image-only Java identity + physical evidence, without source/build inputs."""
import base64
import hashlib
import json
import os
import tempfile
import threading
from pathlib import Path

from .. import payload
from ..acquire import clean_environment, run_command, secret
from ..validation import validate_cyclonedx
from .explicit_identity_gate import prepare
from .seekable_jar_evidence import JarFiles
from .trivy_only_payload import supplement

DB_LOCK = threading.Lock()
VERSION = '0.75.0'


def file_sha(path):
    if not path.is_file() or path.stat().st_size > 2*1024**3:
        raise ValueError('Java database byte budget')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def peer(archive, settings, temporary):
    root = Path(temporary)
    cache = Path(settings.trivy_cache_dir) if settings.trivy_cache_dir else Path.home()/'.cache/sbom-trivy'
    cache.mkdir(parents=True, exist_ok=True)
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
    # A shared service cache is populated only from the scanner's public Java
    # DB distribution, never a repository build cache. Freeze its bytes per scan.
    with DB_LOCK:
        if not database.is_file():
            run_command([settings.trivy_binary, 'image', '--config', str(config), '--cache-dir', str(cache),
                '--download-java-db-only', '--skip-version-check'], cwd=root, env=env,
                timeout=settings.java_db_timeout, max_output_bytes=settings.max_output_bytes,
                monitored_paths=((cache, 2*1024**3),), max_files=10_000, label='Java identity database')
        db_hash = file_sha(database)
    raw = run_command([settings.trivy_binary, 'image', '--config', str(config), '--input', str(archive),
        '--cache-dir', str(cache), '--format', 'cyclonedx', '--offline-scan', '--skip-db-update',
        '--skip-java-db-update', '--skip-version-check'], cwd=root, env=env, timeout=settings.image_timeout,
        max_output_bytes=settings.max_sbom_bytes, monitored_paths=((root, settings.max_archive_bytes),),
        max_files=settings.max_checkout_files, label='Trivy image inventory')
    if file_sha(database) != db_hash:
        raise ValueError('Java database changed during image prediction')
    document = json.loads(raw)
    validate_cyclonedx(document, versions=('1.6', '1.7'))
    return document, {'version': VERSION, 'database_sha256': db_hash,
                      'database_bytes': database.stat().st_size}


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


def corroborate(image, archive, peer_document, *, temporary=None):
    """One resource budget shared by Syft and Trivy-only physical witnesses."""
    files = JarFiles(archive, image, temporary=temporary)
    try:
        observed = payload.collect(image, archive, files_factory=lambda *args: files,
                                   java_witness=lambda artifact, reader: reader.witness(artifact), close_files=False)
        adapted, _, audit = supplement(image, peer_document, observed, archive, files=files)
        physical, envelope = prepare(adapted, audit)
        # Non-Java evidence must not change when enabling Java corroboration.
        for artifact in image['artifacts']:
            if artifact.get('foundBy') != 'java-archive-cataloger' and artifact['id'] in observed:
                physical[artifact['id']] = observed[artifact['id']]
        from ..core import checksum
        envelope['payload_sha256'] = checksum(physical)
        return adapted, physical, envelope, {'binding': audit, 'jar_resources': files.stats,
                                             'layer_resources': files.layers_reader.stats}
    finally:
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
        adapted, physical, envelope, audit = corroborate(image, archive, peer_document, temporary=root)
        return adapted, {'payload_evidence': physical, 'identity_binding_envelope': envelope,
            'java_reader_policy': 'stored-nested-windows-full-crc-bounded-range-cache-v1',
            'java_identity_engine': tool, 'java_image_status': 'corroborated',
            '_artifacts': {'image-original.syft.json': image, 'image-peer.cdx.json': peer_document,
                           'image-identity-audit.json': audit}}

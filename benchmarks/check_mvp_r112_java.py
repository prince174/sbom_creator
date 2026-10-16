"""Six existing image-only Java predictions with the newly exported public DB.

Original Syft image inventories and empty-source catalogs are cached. Trivy image
inventory, physical evidence, identity gates and the service publisher are fresh.
No reference, source project, build cache, registry acquisition or download is read.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r112-java-v1'
DATABASE_SHA256 = '491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59'
METADATA_SHA256 = '40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2'
CACHE = ROOT / 'benchmarks/.work/java-db-r112/cache'
CASES = {
    'microservices': ('paired-petclinic-microservices-r104', 'mvp-r108-v1/java/microservices'),
    'boot': ('paired-spring-petclinic-v1', 'mvp-r108-v1/java/boot'),
    'javalin': ('paired-javalin-reactor-v1', 'mvp-r108-v1/java/javalin'),
    'dropwizard': ('paired-dropwizard-reactor-v1', 'mvp-r108-v1/java/dropwizard'),
    'rest': ('paired-petclinic-rest-v1', 'mvp-r110-held-controls-v1/rest'),
    'dbcp': ('paired-commons-dbcp-v1', 'mvp-r110-held-controls-v1/dbcp'),
}
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(document, indent=2) + '\n')


def require_release_defaults(settings):
    if (settings.java_archive_components is not True or settings.java_nested_windows is not False
            or settings.java_image_evidence is not True or settings.java_backend != 'disabled'):
        raise ValueError('Actual Java component release defaults and disabled source backend are required')


def input_cases(root=ROOT):
    """Fixed cached producer inputs, never selected by oracle coordinates or SHA."""
    rows = []
    for name, (pair, prior) in CASES.items():
        previous = root / 'benchmarks/results' / prior / 'analysis'
        catalog = previous / 'image-original.syft.json'
        source = previous / 'source.syft.json'
        document, no_source = read(catalog), read(source)
        descriptor = document.get('descriptor', {})
        image = document.get('source', {})
        metadata = image.get('metadata', {})
        manifest, config = metadata.get('manifestDigest'), metadata.get('imageID')
        if (descriptor.get('name') != 'syft' or descriptor.get('version') != '1.51.1'
                or image.get('type') != 'image'
                or any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in (manifest, config))):
            raise ValueError('Original pinned Syft image/config binding is required')
        if (no_source.get('artifacts') != [] or no_source.get('artifactRelationships') != []
                or no_source.get('descriptor', {}).get('name') != 'syft'
                or no_source.get('descriptor', {}).get('version') != '1.51.1'):
            raise ValueError('Only the previously scanned empty source catalog is allowed')
        archive = root / 'benchmarks/.work' / pair / 'image.tar'
        if not archive.is_file():
            raise ValueError('Existing immutable archive is required; no acquisition fallback')
        rows.append({'name': name, 'pair': pair, 'archive': archive,
            'original_syft_catalog': catalog, 'empty_source_catalog': source,
            'image': 'docker.io/library/sbom-r112-input@' + manifest,
            'previously_observed_manifest_digest': manifest,
            'previously_observed_config_digest': config})
    return rows


def serialize_case(case, root=ROOT):
    return {key: (value.relative_to(root).as_posix() if isinstance(value, Path) else value)
            for key, value in case.items()}


def offline_peer_command(args, **kwargs):
    """Validate the fresh Trivy command before its process is allowed to start."""
    del kwargs
    if '--download-java-db-only' in args:
        raise AssertionError('New exported public cache must be reused without downloads')
    if len(args) < 2 or (args[1] != 'version' and not (
            args[1] == 'image' and all(flag in args for flag in (
                '--input', '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-version-check')))):
        raise AssertionError('Only version and offline Trivy image inventory commands are allowed')


def forbidden(*_args, **_kwargs):
    raise AssertionError('R112 prediction forbids project/source/registry acquisition or download')


def code_hashes(source):
    return {path.relative_to(source).as_posix(): sha(path) for path in sorted(source.rglob('*'))
            if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--cache', type=Path, default=CACHE)
    args = parser.parse_args()
    output, cache = args.output.resolve(), args.cache.absolute()
    if output.exists():
        raise FileExistsError('Preserve every completed or attempted six-case prediction namespace')
    if cache != CACHE.absolute():
        raise ValueError('Only the separately exported new public cache is allowed')
    database, metadata = cache / 'java-db/trivy-java.db', cache / 'java-db/metadata.json'
    if sha(database) != DATABASE_SHA256 or sha(metadata) != METADATA_SHA256:
        raise ValueError('New public database/metadata differs from the isolated cold-download export')
    cases = input_cases()
    source = ROOT / 'src/sbom_creator'
    source_hashes = code_hashes(source)
    if len(source_hashes) != 48:
        raise ValueError('Exactly 48 current source/schema files must be frozen before execution')
    snapshot = output / 'executed-source'
    shutil.copytree(source, snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    (output / 'executed-runner.py').write_bytes(Path(__file__).read_bytes())
    if code_hashes(snapshot / 'sbom_creator') != source_hashes:
        raise ValueError('Snapshot differs from current service before prediction')
    tools = {'syft': ROOT / '.tools/syft/syft.exe',
             'trivy': ROOT / 'benchmarks/.work/trivy-r34/trivy.exe',
             'crane': ROOT / 'benchmarks/.work/crane-r94/crane.exe'}
    inputs = [database, metadata, *(case[key] for case in cases for key in
        ('archive', 'original_syft_catalog', 'empty_source_catalog'))]
    frozen = {'frozen_at': datetime.now(UTC).isoformat(), 'oracle_read': False,
        'source_input': False, 'project_execution': False, 'reference_build_cache_read': False,
        'fresh_syft_image_scans': False, 'fresh_trivy_image_scans': True,
        'fresh_physical_reads': True, 'actual_service_publisher': True,
        'mode': 'cached original Syft; fresh offline Trivy and physical/identity gates; actual current service publisher',
        'fresh_blind_independent_claim': False, 'java_archive_components_default': True,
        'java_archive_components_override_supplied': False, 'java_nested_windows_default': False,
        'network_downloads_permitted': False, 'build_or_registry_acquisition_permitted': False,
        'cases': list(CASES), 'runner_sha256': sha(Path(__file__)),
        'code_sha256': {'sbom_creator/' + name: digest for name, digest in source_hashes.items()},
        'tool_sha256': {name: sha(path) for name, path in tools.items()},
        'versions_required': {'syft': '1.51.1', 'trivy': '0.75.0'},
        'database_sha256': DATABASE_SHA256, 'database_metadata_sha256': METADATA_SHA256,
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in inputs},
        'inputs': [serialize_case(case) for case in cases]}
    write(output / 'freeze.json', frozen)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot))
    from sbom_creator import pipeline, scanner
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java import runtime
    from sbom_creator.validation import validate_cyclonedx, validate_syft

    if any(not Path(module.__file__).is_relative_to(snapshot) for module in (pipeline, scanner, runtime)):
        raise ValueError('Runtime must import the exact pre-prediction service snapshot')
    require_release_defaults(Settings())
    original_command = runtime.run_command
    commands = []

    def guarded_command(args, **kwargs):
        offline_peer_command(args, **kwargs)
        commands.append({'command_kind': args[1], 'label': kwargs.get('label'),
                         'offline_image_scan': '--offline-scan' in args})
        return original_command(args, **kwargs)

    runtime.run_command = guarded_command
    runtime.acquire = forbidden
    for name in ('checkout', 'scan_source', 'scan_image', 'resolve_java'):
        setattr(pipeline, name, forbidden)
    complete, failed = [], []
    for case in cases:
        target = output / case['name']
        invocation = serialize_case(case)
        invocation.update(oracle_read=False, source_input=False, repository_url=None, commit=None,
            project_execution=False, fresh_syft_image_scan=False, fresh_trivy_image_scan=True,
            fresh_physical_reads=True, actual_service_publisher=True,
            java_archive_components_default=True, java_archive_components_override_supplied=False,
            archive_sha256=frozen['input_sha256'][case['archive'].relative_to(ROOT).as_posix()],
            database_sha256=DATABASE_SHA256, database_metadata_sha256=METADATA_SHA256)
        write(target / 'invocation.json', invocation)
        started, command_start = time.monotonic(), len(commands)
        try:
            image, empty = read(case['original_syft_catalog']), read(case['empty_source_catalog'])
            validate_syft(image)
            validate_syft(empty)
            settings = Settings(syft_binary=str(tools['syft']), trivy_binary=str(tools['trivy']),
                crane_binary=str(tools['crane']), trivy_cache_dir=str(cache),
                image_archive=str(case['archive']), registry_hosts=('docker.io',), java_backend='disabled',
                image_temp_dir=str(ROOT / 'benchmarks/.work/mvp-r112-temporary'))
            require_release_defaults(settings)
            identity = scanner._image_identity(image, case['image'], settings)
            if identity['image_config_digest'] != case['previously_observed_config_digest']:
                raise ValueError('Cached producer image config binding differs')
            image_started = time.monotonic()
            adapted, extra = runtime.analyze(copy.deepcopy(image), identity, settings)
            image_seconds = time.monotonic() - image_started
            engine = extra['java_identity_engine']
            if (engine['database_sha256'] != DATABASE_SHA256
                    or engine['database_metadata_sha256'] != METADATA_SHA256
                    or engine['java_database_cache_status'] != 'reused'
                    or engine['java_database_download_seconds'] != 0):
                raise ValueError('Only validated reuse of the newly exported DB is allowed')
            provenance = {'mode': 'rules', 'source_kind': 'not-provided',
                'request': {'repository_url': None, 'commit': None, 'image': case['image']},
                'image': {**identity, **extra}, 'prediction_inputs': {
                    'image_syft_inventory': 'cached original Syft 1.51.1',
                    'trivy_inventory': 'fresh offline image scan', 'source_project': 'not provided'}}
            summary = pipeline.publish_catalogs(empty, adapted, target / 'analysis',
                settings, pipeline.rules_assessor, provenance)
            for view in ('final', 'os', 'full'):
                validate_cyclonedx(read(target / 'analysis' / (view + '.cdx.json')))
            run = {'status': 'completed', 'oracle_read': False, 'source_input': False,
                'elapsed_seconds': time.monotonic() - started,
                'fresh_trivy_and_physical_seconds': image_seconds, 'summary': summary,
                'fresh_syft_image_scan': False, 'fresh_trivy_image_scan': True,
                'fresh_physical_reads': True, 'actual_service_publisher': True,
                'java_archive_components_default': settings.java_archive_components,
                'observed_config_matches_prior_producer': True,
                'java_identity_engine': engine, 'commands': commands[command_start:],
                'output_sha256': {path.name: sha(path) for path in sorted((target / 'analysis').iterdir()) if path.is_file()},
                'timing': 'fresh Trivy/physical/publisher; cached Syft and local archive, excludes acquisition/download',
                'peak_rss': None}
            complete.append(case['name'])
        except Exception as error:  # noqa: BLE001 -- fixed, non-secret negative evidence
            failed.append(case['name'])
            run = {'status': 'FAILED', 'oracle_read': False, 'source_input': False,
                'elapsed_seconds': time.monotonic() - started, 'error_type': type(error).__name__,
                'error_stage': getattr(error, 'stage', None), 'commands': commands[command_start:],
                'final_published': (target / 'analysis/final.cdx.json').is_file()}
        write(target / 'run.json', run)
        print(case['name'], run['status'], flush=True)
    for name, digest in frozen['input_sha256'].items():
        if sha(ROOT / name) != digest:
            raise ValueError('Frozen DB/archive/catalog input changed; no evaluator marker may be emitted')
    if code_hashes(source) != source_hashes or code_hashes(snapshot / 'sbom_creator') != source_hashes:
        raise ValueError('Frozen service source changed; no evaluator marker may be emitted')
    if any(sha(path) != frozen['tool_sha256'][name] for name, path in tools.items()):
        raise ValueError('Pinned tool changed during predictions')
    write(output / 'predictions-complete.json', {'oracle_read': False, 'cases': list(CASES),
        'completed': complete, 'failed': failed, 'freeze_sha256': sha(output / 'freeze.json'),
        'run_sha256': {name: sha(output / name / 'run.json') for name in CASES},
        'all_predictions_terminal_before_reference_access': True,
        'all_frozen_source_tool_database_image_catalog_inputs_unchanged': True})
    return 0 if not failed else 2


if __name__ == '__main__':
    raise SystemExit(main())

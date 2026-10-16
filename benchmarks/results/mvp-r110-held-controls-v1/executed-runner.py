"""Prepare/freeze then run two held-from-recent-tuning image-only controls.

This runner never opens build references, packaging labels or project caches.
Both Syft and Trivy image inventories, physical reads and publication are fresh.
No project build is attempted. The evaluator is a different explicit command.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json

OUTPUT = ROOT / 'benchmarks/results/mvp-r110-held-controls-v1'
CASES = {'rest': 'paired-petclinic-rest-v1', 'dbcp': 'paired-commons-dbcp-v1'}
EXPECTED_SYFT = '1.51.1'
EXPECTED_TRIVY = '0.75.0'
DB_SHA256 = 'c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def input_cases(root=ROOT):
    """Read only old producer image metadata, never reference components."""
    result = []
    for name, pair in CASES.items():
        work = root / 'benchmarks/.work' / pair
        producer_path = work / 'analysis/image.syft.json'
        document = read(producer_path)
        source, descriptor = document.get('source', {}), document.get('descriptor', {})
        metadata = source.get('metadata', {})
        if (source.get('type') != 'image' or descriptor.get('name') != 'syft'
                or descriptor.get('version') != EXPECTED_SYFT):
            raise ValueError('Previously observed image producer/version is missing')
        config, manifest = metadata.get('imageID', ''), metadata.get('manifestDigest', '')
        if any(not isinstance(value, str) or not re.fullmatch('sha256:[a-f0-9]{64}', value)
               for value in (config, manifest)):
            raise ValueError('Previously observed image/config digest is invalid')
        archive = work / 'image.tar'
        if not archive.is_file():
            raise ValueError('The existing immutable image archive is required')
        result.append({'name': name, 'pair': pair, 'archive': archive,
            'observed_producer_catalog': producer_path,
            'image': 'docker.io/library/sbom-held-control@' + manifest,
            'previously_observed_manifest_digest': manifest,
            'previously_observed_config_digest': config})
    return result


def require_release_defaults(settings):
    """No true override can disguise an unchanged false production default."""
    if settings.java_archive_components is not True or settings.java_image_evidence is not True:
        raise ValueError('R110 requires the release archive-component defaults before execution')


def safe_relative(value):
    path = Path(value)
    if (path.is_absolute() or value.startswith('/') or '..' in path.parts or ':' in value or '\\' in value
            or not value or value.startswith('benchmarks/references/')):
        raise ValueError('Unsafe or oracle prediction input path')
    return path


def seal_outputs(analysis):
    return {path.name: sha(path) for path in sorted(analysis.iterdir()) if path.is_file()}


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve every completed and attempted control namespace')
    cases = input_cases()
    snapshot = OUTPUT / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, OUTPUT / 'executed-runner.py')
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.pipeline import analyze
    from sbom_creator.validation import validate_cyclonedx

    if not Path(sys.modules['sbom_creator.pipeline'].__file__).is_relative_to(snapshot):
        raise ValueError('Service did not import the exact executing snapshot')
    require_release_defaults(Settings())
    tools = {'syft': ROOT / '.tools/syft/syft.exe',
             'trivy': ROOT / 'benchmarks/.work/trivy-r34/trivy.exe',
             'crane': ROOT / 'benchmarks/.work/crane-r94/crane.exe'}
    cache = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache'
    database, metadata = cache / 'java-db/trivy-java.db', cache / 'java-db/metadata.json'
    if sha(database) != DB_SHA256:
        raise ValueError('Pinned public Java database differs; do not download silently')
    inputs = [database, metadata]
    inputs.extend(case[key] for case in cases for key in ('archive', 'observed_producer_catalog'))
    freeze = {'oracle_read': False, 'source_input': False, 'project_execution': False,
        'fresh_scanners': True, 'fresh_physical_reads': True, 'actual_service_publisher': True,
        'execution_mode': 'image-only release default; fresh Syft/Trivy/physical/publisher',
        'partition': 'existing controls held from recent Java reader/identity tuning; historically disclosed',
        'fresh_blind_independent_claim': False,
        'java_archive_components_default': True, 'java_archive_components_override_supplied': False,
        'java_nested_windows_default': Settings().java_nested_windows,
        'cases': [case['name'] for case in cases], 'runner_sha256': sha(__file__),
        'code_sha256': {path.relative_to(snapshot).as_posix(): sha(path)
                       for path in sorted(snapshot.rglob('*')) if path.is_file()},
        'tool_sha256': {name: sha(path) for name, path in tools.items()},
        'versions_required': {'syft': EXPECTED_SYFT, 'trivy': EXPECTED_TRIVY},
        'database_sha256': DB_SHA256,
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in inputs},
        'inputs': [{key: (value.relative_to(ROOT).as_posix() if isinstance(value, Path) else value)
                    for key, value in case.items()} for case in cases]}
    atomic_json(OUTPUT / 'freeze.json', freeze)
    complete, failed = [], []
    for case in cases:
        target = OUTPUT / case['name']
        invocation = {key: (value.relative_to(ROOT).as_posix() if isinstance(value, Path) else value)
                      for key, value in case.items()}
        invocation.update(archive_sha256=sha(case['archive']), repository_url=None, commit=None,
            source_input=False, project_execution=False, oracle_read=False,
            fresh_scanners=True, fresh_physical_reads=True,
            java_archive_components_default=True, java_archive_components_override_supplied=False)
        atomic_json(target / 'invocation.json', invocation)
        settings = Settings(syft_binary=str(tools['syft']), trivy_binary=str(tools['trivy']),
            crane_binary=str(tools['crane']), trivy_cache_dir=str(cache),
            image_archive=str(case['archive']), registry_hosts=('docker.io',), java_backend='disabled',
            image_temp_dir=str(ROOT / 'benchmarks/.work/mvp-r110-temporary'))
        require_release_defaults(settings)
        started = time.monotonic()
        try:
            summary = analyze(None, None, case['image'], target / 'analysis', settings)
            for view in ('final', 'os', 'full'):
                validate_cyclonedx(read(target / 'analysis' / (view + '.cdx.json')))
            provenance = read(target / 'analysis/provenance.json')
            observed = provenance.get('image', {}).get('image_config_digest')
            atomic_json(target / 'run.json', {'status': 'completed', 'oracle_read': False,
                'fresh_scanners': True, 'fresh_physical_reads': True,
                'source_input': False, 'elapsed_seconds': time.monotonic() - started,
                'summary': summary, 'java_archive_components_default': settings.java_archive_components,
                'observed_config_matches_prior_producer': observed == case['previously_observed_config_digest'],
                'output_sha256': seal_outputs(target / 'analysis'),
                'timing': 'fresh scans/physical/publisher; local archive excludes registry acquisition',
                'peak_rss': None})
            complete.append(case['name'])
            print(case['name'], 'completed', summary['final_count'], flush=True)
        except Exception as error:  # noqa: BLE001 -- preserve safe negative outcomes
            failed.append(case['name'])
            atomic_json(target / 'run.json', {'status': 'FAILED', 'oracle_read': False,
                'fresh_scanners': True, 'fresh_physical_reads': True, 'source_input': False,
                'elapsed_seconds': time.monotonic() - started, 'error_type': type(error).__name__,
                'error_stage': getattr(error, 'stage', None),
                'final_published': (target / 'analysis/final.cdx.json').is_file()})
            print(case['name'], 'FAILED', type(error).__name__, flush=True)
    for relative, digest in freeze['input_sha256'].items():
        if sha(ROOT / safe_relative(relative)) != digest:
            raise ValueError('Frozen input changed; evaluator marker will not be published')
    atomic_json(OUTPUT / 'predictions-complete.json', {'oracle_read': False,
        'cases': [case['name'] for case in cases], 'completed': complete, 'failed': failed,
        'freeze_sha256': sha(OUTPUT / 'freeze.json'),
        'run_sha256': {name: sha(OUTPUT / name / 'run.json') for name in CASES},
        'all_predictions_terminal_before_reference_access': True})


if __name__ == '__main__':
    main()

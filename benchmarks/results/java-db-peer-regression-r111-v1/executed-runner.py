"""Peer-only warm public DB integration parity, without physical/publisher work.

Existing R110 image-peer inventories are baselines, never reference/oracle labels.
Only Trivy image inventory is fresh. No source, Syft, build or payload reader.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from run import ROOT, atomic_json

OUTPUT = ROOT / 'benchmarks/results/java-db-peer-regression-r111-v1'
CASES = {'rest': 'paired-petclinic-rest-v1', 'dbcp': 'paired-commons-dbcp-v1'}
PIN = 'c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25'


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def image_id(document):
    values = [entry.get('value') for entry in document.get('metadata', {}).get('component', {}).get('properties', [])
              if entry.get('name') == 'aquasecurity:trivy:ImageID']
    if len(values) != 1:
        raise ValueError('Unique image config identity is required')
    return values[0]


def component_instances(document):
    def walk(components):
        for component in components:
            yield component
            yield from walk(component.get('components', []))
    values = list(walk(document.get('components', [])))
    values.extend(walk(document.get('metadata', {}).get('component', {}).get('components', [])))
    return Counter(json.dumps([*(component.get(key) for key in ('type', 'group', 'name', 'version', 'purl')),
        sorted(json.dumps(value, sort_keys=True, separators=(',', ':')) for value in component.get('properties', []))],
        sort_keys=True, separators=(',', ':')) for component in values)


def forbidden(*_args, **_kwargs):
    raise AssertionError('Peer-only regression forbids acquisition, physical evidence and publication')


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve peer-only integration attempts')
    snapshot = OUTPUT / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, OUTPUT / 'executed-runner.py')
    code = {path.relative_to(snapshot).as_posix(): sha(path)
            for path in sorted(snapshot.rglob('*')) if path.is_file()}
    cache = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache'
    database, metadata = cache / 'java-db/trivy-java.db', cache / 'java-db/metadata.json'
    trivy = ROOT / 'benchmarks/.work/trivy-r34/trivy.exe'
    inputs = [database, metadata]
    paths = {}
    for name, pair in CASES.items():
        archive = ROOT / 'benchmarks/.work' / pair / 'image.tar'
        prior = ROOT / 'benchmarks/results/mvp-r110-held-controls-v1' / name / 'analysis/image-peer.cdx.json'
        paths[name] = archive, prior
        inputs.extend((archive, prior))
    if sha(database) != PIN:
        raise ValueError('Existing pinned public cache changed before peer integration')
    freeze = {'oracle_read': False, 'physical_reader_called': False, 'publisher_called': False,
        'syft_called': False, 'project_build_or_source_input': False,
        'fresh_trivy_image_scan': True, 'new_accuracy_measurement': False,
        'warm_existing_cache_only': True, 'database_sha256': PIN,
        'runner_sha256': sha(__file__), 'code_sha256': code,
        'trivy_sha256': sha(trivy),
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in inputs}}
    atomic_json(OUTPUT / 'freeze.json', freeze)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java import java_database_cache, runtime
    from sbom_creator.validation import validate_cyclonedx

    if (not Path(runtime.__file__).is_relative_to(snapshot)
            or runtime.ensure_database is not java_database_cache.ensure):
        raise ValueError('New cache ensure helper must be wired in the exact frozen runtime')
    actual_command = runtime.run_command
    ensure = runtime.ensure_database
    commands, helper_results = [], []

    def guarded_command(args, **kwargs):
        if '--download-java-db-only' in args:
            raise AssertionError('A valid existing public cache must not be downloaded/refreshed')
        if (args[1] != 'version' and not (args[1] == 'image' and '--input' in args
                and '--offline-scan' in args and '--skip-java-db-update' in args)):
            raise AssertionError('Only pinned version and offline image-peer commands are allowed')
        commands.append({'command_kind': args[1], 'label': kwargs.get('label')})
        return actual_command(args, **kwargs)

    def tracked_ensure(cache_path, downloader):
        facts = ensure(cache_path, downloader)
        helper_results.append(facts)
        return facts

    runtime.run_command = guarded_command
    runtime.ensure_database = tracked_ensure
    runtime.corroborate = forbidden
    runtime.acquire = forbidden
    runtime.payload.collect = forbidden
    settings = Settings(trivy_binary=str(trivy), trivy_cache_dir=str(cache))
    results = []
    for name, (archive, prior) in paths.items():
        target = OUTPUT / name
        target.mkdir()
        before_calls, before_helper = len(commands), len(helper_results)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='peer-r111-', dir=target) as temporary:
            actual, tool = runtime.peer(archive, settings, temporary)
        elapsed = time.monotonic() - started
        validate_cyclonedx(actual, versions=('1.6', '1.7'))
        baseline = json.loads(prior.read_bytes())
        if (component_instances(actual) != component_instances(baseline)
                or image_id(actual) != image_id(baseline)):
            atomic_json(target / 'image-peer.cdx.json', actual)
            raise ValueError('Raw peer GAV/path/layer instances changed after cache integration')
        if (tool.get('database_sha256') != PIN or tool.get('java_database_cache_status') != 'reused'
                or len(helper_results) - before_helper != 1):
            raise ValueError('Expected exactly one validated warm cache reuse')
        atomic_json(target / 'image-peer.cdx.json', actual)
        report = {'status': 'PASS', 'oracle_read': False, 'seconds': elapsed,
            'raw_component_instances_equal': True, 'image_config_equal': True,
            'raw_component_count': sum(component_instances(actual).values()),
            'compared_fields': 'type/group/name/version/PURL and all producer properties including exact FilePath/LayerDiffID/LayerDigest',
            'tool': tool, 'cache_helper_calls': len(helper_results) - before_helper,
            'allowed_commands': commands[before_calls:], 'fresh_trivy_image_scan': True,
            'syft_or_physical_reader_or_publisher': False,
            'baseline_sha256': sha(prior), 'raw_output_sha256': sha(target / 'image-peer.cdx.json')}
        atomic_json(target / 'run.json', report)
        results.append({'case': name, **report})
        print(name, 'peer-only raw instances unchanged', report['raw_component_count'], flush=True)
    for relative, expected in freeze['input_sha256'].items():
        if sha(ROOT / relative) != expected:
            raise ValueError('Frozen peer cache/image/baseline changed')
    for relative, expected in code.items():
        if sha(snapshot / relative) != expected or sha(ROOT / 'src' / relative) != expected:
            raise ValueError('Classifier/cache source changed during integration regression')
    atomic_json(OUTPUT / 'report.json', {'status': 'PASS', 'cases': results,
        'oracle_read': False, 'new_accuracy_measurement': False,
        'fresh_trivy_image_scans': len(results), 'physical_or_publisher_runs': 0,
        'network_download_attempts': 0, 'existing_public_db_sha256_unchanged': PIN,
        'warm_cache_reuses': len(helper_results), 'freeze_sha256': sha(OUTPUT / 'freeze.json')})


if __name__ == '__main__':
    main()

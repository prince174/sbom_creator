"""Two cached publisher regressions; no scanner, physical reader or oracle.

Preserve the original R106 Chalk failure. Successful cached replay is not a
historical locking fix or a new accuracy result. Run only after root SRC READY.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r113-publication-v1'
VIEWS = ('final', 'os', 'full')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(document, indent=2) + '\n')


def code_hashes(source):
    return {path.relative_to(source).as_posix(): sha(path) for path in sorted(source.rglob('*'))
            if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}


def input_cases(root=ROOT):
    results = root / 'benchmarks/results'
    return [
        {'name': 'chalk-original-r106',
         'inputs': results / 'mvp-r106-v1/javascript/paired-chalk-v1/analysis.diagnostics',
         'baseline': results / 'chalk-publish-diagnostic-v1/analysis'},
        {'name': 'nest-types-r109',
         'inputs': results / 'mvp-js-types-r109-v1/paired-nest-starter-v1/analysis',
         'baseline': results / 'mvp-js-types-r109-v1/paired-nest-starter-v1/analysis'},
    ]


def coordinates(document):
    def walk(items):
        for component in items:
            yield component
            yield from walk(component.get('components', []))
    components = [*walk(document.get('components', [])), *walk(
        document.get('metadata', {}).get('component', {}).get('components', []))]
    return Counter(json.dumps([component.get(key) for key in ('type', 'group', 'name', 'version', 'purl')],
                              separators=(',', ':')) for component in components)


def selected_ids(document):
    return sorted(artifact['id'] for artifact in document['artifacts'])


def cached_inputs_valid(source, image, provenance):
    if (source.get('artifacts') != [] or provenance.get('source_kind') != 'not-provided'
            or provenance.get('request', {}).get('repository_url') is not None
            or provenance.get('request', {}).get('commit') is not None
            or image.get('source', {}).get('type') != 'image'
            or image.get('descriptor', {}).get('name') != 'syft'
            or image.get('descriptor', {}).get('version') != '1.51.1'
            or not isinstance(provenance.get('image', {}).get('payload_evidence'), dict)):
        raise ValueError('Only original cached image-only catalogs and actual payload facts are eligible')


def forbidden(*_args, **_kwargs):
    raise AssertionError('Cached publication forbids scanning, acquisition, project execution, physical reads and oracle')


def convert_only(delegate, calls):
    def guarded(args, config, *, output):
        if not args or args[0] != 'convert':
            raise AssertionError('Only the pinned Syft converter may execute')
        calls.append('convert')
        return delegate(args, config, output=output)
    return guarded


def compare_published(target, baseline, original_payload, validate):
    views = {}
    for view in VIEWS:
        path = target / (view + '.cdx.json')
        current = read(path)
        validate(current)
        if coordinates(current) != coordinates(read(baseline / path.name)):
            raise ValueError('Published component-coordinate instances changed')
        views[view] = {'component_count': sum(coordinates(current).values()),
                       'coordinate_multiset_equal': True, 'schema_valid': True, 'sha256': sha(path)}
    if selected_ids(read(target / 'selected.syft.json')) != selected_ids(read(baseline / 'selected.syft.json')):
        raise ValueError('Selected artifact IDs changed')
    published = read(target / 'provenance.json')['image']['payload_evidence']
    if published != original_payload:
        raise ValueError('Original complete physical/type payload mapping changed')
    return {'views': views, 'selected_artifact_ids_equal': True, 'all_original_payload_facts_equal': True,
            'declared_type_witness_count': sum(fact.get('payload_kind') == 'declared_type_surface'
                                                for fact in published.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--root-source-ready', action='store_true')
    args = parser.parse_args()
    if not args.root_source_ready:
        raise ValueError('Wait for explicit root final 49-source freeze READY')
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError('Preserve every completed or attempted publication namespace')
    cases = input_cases()
    failure_dir = ROOT / 'benchmarks/results/mvp-r106-v1/javascript/paired-chalk-v1'
    history = [failure_dir / 'run.json', failure_dir / 'analysis.diagnostics/failure.json']
    if (read(history[0]).get('status') != 'FAILED'
            or read(history[1]).get('error_type') != 'PermissionError'
            or read(history[1]).get('final_published') is not False):
        raise ValueError('The original historical failed publication must remain preserved')
    names = ('source.syft.json', 'image.syft.json', 'provenance.json')
    inputs = [*history, *(case['inputs'] / name for case in cases for name in names),
              *(case['baseline'] / name for case in cases for name in (
                  *(view + '.cdx.json' for view in VIEWS), 'selected.syft.json'))]
    source = ROOT / 'src/sbom_creator'
    source_hashes = code_hashes(source)
    if len(source_hashes) != 49:
        raise ValueError('Exactly 49 current source/schema files must be frozen before publication')
    snapshot = output / 'executed-source'
    shutil.copytree(source, snapshot / 'sbom_creator', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output / 'executed-runner.py')
    if code_hashes(snapshot / 'sbom_creator') != source_hashes:
        raise ValueError('Source changed while creating the execution snapshot')
    syft = ROOT / '.tools/syft/syft.exe'
    freeze = {'oracle_read': False, 'fresh_scanners': False, 'fresh_physical_reads': False,
        'source_input': False, 'project_execution': False, 'new_accuracy_measurement': False,
        'historical_chalk_failure_fixed_claim': False, 'root_source_ready_explicit': True,
        'mode': 'actual publisher only; original cached catalogs and physical/type payload mappings',
        'runner_sha256': sha(__file__), 'syft_converter_sha256': sha(syft),
        'code_sha256': {'sbom_creator/' + name: digest for name, digest in source_hashes.items()},
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in inputs},
        'cases': [{key: value.relative_to(ROOT).as_posix() if isinstance(value, Path) else value
                   for key, value in case.items()} for case in cases]}
    write(output / 'freeze.json', freeze)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot))
    from sbom_creator import acquire, build_backend, payload, pipeline, scanner
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java import runtime
    from sbom_creator.validation import validate_cyclonedx

    if any(not Path(module.__file__).is_relative_to(snapshot) for module in
           (pipeline, scanner, runtime, payload, build_backend)):
        raise ValueError('Publisher must execute the frozen source snapshot')
    for module, name in ((acquire, 'checkout'), (build_backend, 'resolve'), (payload, 'collect'),
            (scanner, 'scan_source'), (scanner, 'scan_image'), (scanner, 'collect_payload'),
            (pipeline, 'checkout'), (pipeline, 'scan_source'), (pipeline, 'scan_image'),
            (pipeline, 'resolve_java'), (runtime, 'acquire'), (runtime, 'peer'),
            (runtime, 'analyze'), (runtime, 'corroborate')):
        setattr(module, name, forbidden)
    calls = []
    scanner._syft = convert_only(scanner._syft, calls)
    settings = Settings(syft_binary=str(syft), java_backend='disabled')
    reports, started = [], time.monotonic()
    for case in cases:
        target, before, call_start = output / case['name'], time.monotonic(), len(calls)
        source_doc, image, provenance = (read(case['inputs'] / name) for name in names)
        cached_inputs_valid(source_doc, image, provenance)
        original_payload = json.loads(json.dumps(provenance['image']['payload_evidence']))
        try:
            summary = pipeline.publish_catalogs(source_doc, image, target / 'analysis',
                settings, pipeline.rules_assessor, provenance)
            parity = compare_published(target / 'analysis', case['baseline'], original_payload, validate_cyclonedx)
            if (len(calls) - call_start != 1 or summary['policy_version'] != 'image-evidence-and-payload-v4'
                    or read(target / 'analysis/source.syft.json') != read(case['inputs'] / 'source.syft.json')
                    or read(target / 'analysis/image.syft.json') != read(case['inputs'] / 'image.syft.json')):
                raise ValueError('Publisher changed cached inputs, policy or conversion contract')
            report = {'status': 'passed', 'summary': summary, **parity,
                'source_image_catalogs_unchanged': True,
                'output_sha256': {path.name: sha(path) for path in sorted((target / 'analysis').iterdir()) if path.is_file()}}
        except Exception as error:  # noqa: BLE001 -- fixed bounded type/stage fields, no raw diagnostics
            report = {'status': 'FAILED', 'error_type': type(error).__name__,
                'stage': getattr(error, 'stage', None), 'final_published': (target / 'analysis/final.cdx.json').is_file()}
        report.update(name=case['name'], oracle_read=False, fresh_scanners=False,
            fresh_physical_reads=False, source_input=False, new_accuracy_measurement=False,
            historical_chalk_failure_fixed_claim=False, conversion_calls=len(calls) - call_start,
            elapsed_seconds=time.monotonic() - before)
        write(target / 'run.json', report)
        reports.append(report)
        print(case['name'], report['status'], flush=True)
    if (any(sha(ROOT / name) != digest for name, digest in freeze['input_sha256'].items())
            or code_hashes(source) != source_hashes or code_hashes(snapshot / 'sbom_creator') != source_hashes
            or sha(syft) != freeze['syft_converter_sha256']):
        raise ValueError('Frozen inputs/source/converter changed during publication')
    write(output / 'report.json', {'status': 'passed' if all(r['status'] == 'passed' for r in reports) else 'FAILED',
        'cases': reports, 'oracle_read': False, 'fresh_scanners': False, 'fresh_physical_reads': False,
        'source_input': False, 'project_execution': False, 'new_accuracy_measurement': False,
        'historical_chalk_failure_preserved': True, 'historical_chalk_failure_fixed_claim': False,
        'all_frozen_inputs_source_converter_unchanged': True,
        'run_sha256': {case['name']: sha(output / case['name'] / 'run.json') for case in cases},
        'conversion_calls': len(calls), 'elapsed_seconds': time.monotonic() - started,
        'freeze_sha256': sha(output / 'freeze.json')})


if __name__ == '__main__':
    main()

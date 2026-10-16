"""R110 current-default publisher regression over all twelve R109 JS catalogs.

No image/source scanning, acquisition, project execution or oracle access.
R109 declared-type evidence is reused verbatim. Original R106 Chalk failure is
retained, although all twelve R109 fresh baseline publications completed.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

from replay_js_publish_r107 import coordinates, selected_ids, sha
from run import ROOT, atomic_json


def read(path):
    return json.loads(path.read_bytes())


def main():
    output = ROOT / 'benchmarks/results/mvp-r110-js-publish-v1'
    if output.exists():
        raise FileExistsError('Preserve every completed or attempted publication regression')
    previous = ROOT / 'benchmarks/results/mvp-js-types-r109-v1'
    marker = read(previous / 'predictions-complete.json')
    if (marker.get('oracle_read') is not False or marker.get('failed')
            or len(marker.get('cases', [])) != 12 or len(marker.get('completed', [])) != 12):
        raise ValueError('All twelve R109 image-only baseline attempts must be complete')
    cases = []
    for name in marker['cases']:
        path = previous / name
        baseline = read(path / 'run.json')
        if baseline['status'] != 'completed' or baseline.get('oracle_read') is not False:
            raise ValueError('Each R109 baseline must be a completed isolated prediction')
        cases.append({'name': name, 'baseline': path / 'analysis', 'run': path / 'run.json'})
    if len({case['name'] for case in cases}) != 12:
        raise ValueError('Duplicate baseline names')
    snapshot = output / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output / 'executed-runner.py')
    shutil.copyfile(ROOT / 'benchmarks/replay_js_publish_r107.py', output / 'executed-coordinate-helper.py')
    names = ('source.syft.json', 'image.syft.json', 'provenance.json', 'selected.syft.json',
             'final.cdx.json', 'os.cdx.json', 'full.cdx.json')
    paths = [case['baseline'] / name for case in cases for name in names]
    paths.extend(case['run'] for case in cases)
    paths.append(previous / 'predictions-complete.json')
    chalk_failure = ROOT / 'benchmarks/results/mvp-r106-v1/javascript/paired-chalk-v1/run.json'
    if read(chalk_failure)['status'] != 'FAILED':
        raise ValueError('Historical Chalk publication failure must remain preserved')
    paths.append(chalk_failure)
    syft = ROOT / '.tools/syft/syft.exe'
    code_hashes = {path.relative_to(snapshot).as_posix(): sha(path)
                   for path in sorted(snapshot.rglob('*')) if path.is_file()}
    if len(code_hashes) != 47:
        raise ValueError('Expected current 47 source/schema files')
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'fresh_scans': False,
        'fresh_physical_reads': False, 'source_input': False, 'project_execution': False,
        'new_accuracy_measurement': False, 'java_nested_windows': False,
        'java_archive_components': True, 'uses_current_dataclass_defaults': True,
        'mode': 'real publisher over twelve cached R109 raw catalogs and R109 physical/type evidence',
        'runner_sha256': sha(Path(__file__)),
        'coordinate_helper_sha256': sha(output / 'executed-coordinate-helper.py'),
        'syft_converter_sha256': sha(syft), 'code_sha256': code_hashes,
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in paths},
        'original_chalk_failure': chalk_failure.relative_to(ROOT).as_posix(),
        'baselines': [case['baseline'].relative_to(ROOT).as_posix() for case in cases]})
    sys.path.insert(0, str(snapshot))
    from sbom_creator import acquire, pipeline, scanner
    from sbom_creator.acquire import Settings
    from sbom_creator.core import rules_assessor
    from sbom_creator.image_java import runtime
    from sbom_creator.validation import validate_cyclonedx

    if not Path(sys.modules['sbom_creator.pipeline'].__file__).is_relative_to(snapshot):
        raise ValueError('The publisher must execute its frozen source snapshot')
    settings = Settings(syft_binary=str(syft), java_backend='disabled')
    if not settings.java_archive_components or settings.java_nested_windows:
        raise ValueError('R110 release defaults were not selected')

    def forbidden(*args, **kwargs):
        raise AssertionError('Cached publication cannot acquire, scan, execute or resolve a project')

    for module, name in ((acquire, 'checkout'), (scanner, 'scan_source'), (scanner, 'scan_image'),
                         (pipeline, 'checkout'), (pipeline, 'scan_source'), (pipeline, 'scan_image'),
                         (runtime, 'acquire'), (runtime, 'peer'), (runtime, 'analyze')):
        if hasattr(module, name):
            setattr(module, name, forbidden)
    original_syft = scanner._syft
    converter_calls = []

    def convert_only(args, config, *, output):
        if args[0] != 'convert':
            raise AssertionError('Only conversion is allowed in cached publisher regression')
        converter_calls.append(args[0])
        return original_syft(args, config, output=output)

    scanner._syft = convert_only
    reports, started = [], time.monotonic()
    for case in cases:
        target, before = output / case['name'], time.monotonic()
        source = read(case['baseline'] / 'source.syft.json')
        image = read(case['baseline'] / 'image.syft.json')
        provenance = read(case['baseline'] / 'provenance.json')
        if (source['artifacts'] or provenance.get('source_kind') != 'not-provided'
                or provenance.get('request', {}).get('repository_url') is not None):
            raise ValueError('Cached baseline must remain image-only with empty source')
        cached_payload = provenance.get('image', {}).get('payload_evidence')
        if not isinstance(cached_payload, dict):
            raise TypeError('Use the actual R109 payload/type observations')
        summary = pipeline.publish_catalogs(source, image, target / 'analysis', settings,
                                            rules_assessor, provenance)
        if summary['policy_version'] != 'image-evidence-and-payload-v4':
            raise ValueError('Non-Java base rules policy unexpectedly changed')
        views = {}
        for view in ('final', 'os', 'full'):
            path = target / 'analysis' / (view + '.cdx.json')
            actual = read(path)
            validate_cyclonedx(actual)
            baseline = read(case['baseline'] / (view + '.cdx.json'))
            if coordinates(actual) != coordinates(baseline):
                raise ValueError('R110 publication changed an R109 component-coordinate multiset')
            views[view] = {'coordinates_equal': True, 'component_count': len(actual.get('components', [])),
                           'cyclonedx_schema_valid': True, 'sha256': sha(path)}
        current_ids = selected_ids(read(target / 'analysis/selected.syft.json'))
        if current_ids != selected_ids(read(case['baseline'] / 'selected.syft.json')):
            raise ValueError('R110 publication changed selected artifact IDs')
        published_payload = read(target / 'analysis/provenance.json')['image']['payload_evidence']
        if published_payload != cached_payload:
            raise ValueError('R109 physical and declared-type facts must be preserved verbatim')
        types = {aid: fact for aid, fact in published_payload.items()
                 if fact.get('payload_kind') == 'declared_type_surface'}
        report = {'name': case['name'], 'status': 'passed', 'oracle_read': False,
            'fresh_scans': False, 'fresh_physical_reads': False, 'source_input': False,
            'views': views, 'selected_artifact_ids_equal': True, 'summary': summary,
            'payload_and_type_facts_equal_r109': True, 'declared_type_witness_count': len(types),
            'elapsed_seconds': time.monotonic() - before,
            'baseline': case['baseline'].relative_to(ROOT).as_posix(),
            'original_r106_chalk_failure': case['name'] == 'paired-chalk-v1',
            'locking_failure_fixed': False, 'new_accuracy_measurement': False}
        atomic_json(target / 'run.json', report)
        reports.append(report)
        print(case['name'], 'R110 current-default publisher parity passed', flush=True)
    freeze = read(output / 'freeze.json')
    for path, digest in freeze['input_sha256'].items():
        if sha(ROOT / path) != digest:
            raise ValueError('A frozen R109 input changed during publication regression')
    for path, digest in freeze['code_sha256'].items():
        if sha(snapshot / path) != digest:
            raise ValueError('The executed source snapshot changed')
    atomic_json(output / 'report.json', {'status': 'passed', 'cases': reports,
        'oracle_read': False, 'fresh_scans': False, 'fresh_physical_reads': False,
        'source_input': False, 'project_execution': False,
        'java_archive_components': settings.java_archive_components,
        'java_nested_windows': settings.java_nested_windows, 'uses_current_dataclass_defaults': True,
        'new_accuracy_measurement': False, 'views_equal': 36, 'selected_artifact_id_sets_equal': 12,
        'cached_r109_baselines': 12, 'payload_and_type_facts_equal': True,
        'original_r106_chalk_failure_preserved': True, 'locking_failure_fixed': False,
        'known_conservative_extra_scope_not_filtered': True,
        'conversion_calls': len(converter_calls), 'scan_or_acquisition_calls_allowed': False,
        'elapsed_seconds': time.monotonic() - started, 'freeze_sha256': sha(output / 'freeze.json')})


if __name__ == '__main__':
    main()

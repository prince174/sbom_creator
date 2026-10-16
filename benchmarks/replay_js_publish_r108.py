"""R108 publisher-only JavaScript regression; cached predictions, never oracle.

All twelve R107 cached publisher baselines are reused. Their original R106
Chalk publication failure remains recorded; this is neither a new scanner run
nor proof that an intermittent Windows locking problem was repaired.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

from replay_js_publish_r107 import coordinates, selected_ids, sha
from run import ROOT, atomic_json


def main():
    output = ROOT/'benchmarks/results/mvp-r108-js-publish-v1'
    if output.exists():
        raise FileExistsError('Preserve completed and attempted publisher regressions')
    previous = ROOT/'benchmarks/results/mvp-r107-js-publish-v1'
    cases = []
    for path in sorted(previous.glob('paired-*')):
        baseline_run = json.loads((path/'run.json').read_bytes())
        if baseline_run['status'] != 'passed':
            raise ValueError('A completed cached publisher baseline is required')
        chalk = path.name == 'paired-chalk-v1'
        if chalk and (baseline_run['original_r106_run_status'] != 'FAILED'
                      or baseline_run['locking_failure_fixed'] is not False):
            raise ValueError('The original Chalk failure caveat must remain explicit')
        cases.append({'name': path.name, 'baseline': path/'analysis', 'run': path/'run.json',
                      'original_r106_failed': chalk})
    if len(cases) != 12 or len({case['name'] for case in cases}) != 12:
        raise ValueError('Exactly twelve distinct cached JavaScript baselines are required')
    snapshot = output/'executed-source'
    shutil.copytree(ROOT/'src/sbom_creator', snapshot/'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output/'executed-runner.py')
    shutil.copyfile(ROOT/'benchmarks/replay_js_publish_r107.py', output/'executed-r107-helper.py')
    syft = ROOT/'.tools/syft/syft.exe'
    names = ('source.syft.json', 'image.syft.json', 'provenance.json', 'selected.syft.json',
             'final.cdx.json', 'os.cdx.json', 'full.cdx.json')
    paths = [case['baseline']/name for case in cases for name in names]
    paths.extend(case['run'] for case in cases)
    chalk_failure = ROOT/'benchmarks/results/mvp-r106-v1/javascript/paired-chalk-v1/run.json'
    paths.append(chalk_failure)
    atomic_json(output/'freeze.json', {'oracle_read': False, 'fresh_scans': False,
        'fresh_physical_reads': False, 'source_input': False, 'project_execution': False,
        'java_nested_windows': True, 'java_archive_components': True,
        'production_default_changed': False, 'new_accuracy_measurement': False,
        'mode': 'actual publisher over twelve cached R107 raw catalogs and physical evidence',
        'runner_sha256': sha(Path(__file__)), 'prior_helper_sha256': sha(output/'executed-r107-helper.py'),
        'syft_converter_sha256': sha(syft),
        'code_sha256': {path.relative_to(snapshot).as_posix(): sha(path)
                       for path in sorted(snapshot.rglob('*')) if path.is_file()},
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in paths},
        'original_chalk_failure': chalk_failure.relative_to(ROOT).as_posix(),
        'baselines': [case['baseline'].relative_to(ROOT).as_posix() for case in cases]})
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.core import rules_assessor
    from sbom_creator.pipeline import publish_catalogs
    from sbom_creator.validation import validate_cyclonedx

    if not Path(sys.modules['sbom_creator.pipeline'].__file__).is_relative_to(snapshot):
        raise ValueError('Publisher did not import its frozen source snapshot')
    settings = Settings(syft_binary=str(syft), java_backend='disabled',
                        java_nested_windows=True, java_archive_components=True)
    reports, started = [], time.monotonic()
    for case in cases:
        target, before = output/case['name'], time.monotonic()
        source = json.loads((case['baseline']/'source.syft.json').read_bytes())
        image = json.loads((case['baseline']/'image.syft.json').read_bytes())
        provenance = json.loads((case['baseline']/'provenance.json').read_bytes())
        if source['artifacts'] or provenance.get('request', {}).get('repository_url') is not None:
            raise ValueError('Cached baseline must remain image-only with empty source')
        summary = publish_catalogs(source, image, target/'analysis', settings, rules_assessor, provenance)
        views = {}
        for view in ('final', 'os', 'full'):
            path = target/'analysis'/(view+'.cdx.json')
            actual = json.loads(path.read_bytes())
            validate_cyclonedx(actual)
            baseline = json.loads((case['baseline']/(view+'.cdx.json')).read_bytes())
            if coordinates(actual) != coordinates(baseline):
                raise ValueError('R108 publisher component-coordinate regression')
            views[view] = {'coordinates_equal': True, 'component_count': len(actual.get('components', [])),
                           'cyclonedx_schema_valid': True, 'sha256': sha(path)}
        actual_ids = selected_ids(json.loads((target/'analysis/selected.syft.json').read_bytes()))
        if actual_ids != selected_ids(json.loads((case['baseline']/'selected.syft.json').read_bytes())):
            raise ValueError('R108 publisher selected artifact identity regression')
        report = {'name': case['name'], 'status': 'passed', 'oracle_read': False,
            'fresh_scans': False, 'fresh_physical_reads': False, 'source_input': False,
            'views': views, 'selected_artifact_ids_equal': True, 'summary': summary,
            'elapsed_seconds': time.monotonic()-before,
            'baseline': case['baseline'].relative_to(ROOT).as_posix(),
            'original_r106_chalk_failure': case['original_r106_failed'],
            'locking_failure_fixed': False, 'new_accuracy_measurement': False}
        atomic_json(target/'run.json', report)
        reports.append(report)
        print(case['name'], 'R108 publisher parity passed', flush=True)
    for path, digest in json.loads((output/'freeze.json').read_bytes())['input_sha256'].items():
        if sha(ROOT/path) != digest:
            raise ValueError('Frozen cached input changed during R108 regression')
    atomic_json(output/'report.json', {'status': 'passed', 'cases': reports,
        'oracle_read': False, 'fresh_scans': False, 'fresh_physical_reads': False, 'source_input': False,
        'java_nested_windows': True, 'java_archive_components': True, 'production_default_changed': False,
        'new_accuracy_measurement': False, 'views_equal': 36, 'selected_artifact_id_sets_equal': 12,
        'cached_r107_baselines': 12, 'original_r106_fresh_scan_successes': 11,
        'separate_chalk_diagnostic_in_history': True, 'original_chalk_failure_preserved': True,
        'locking_failure_fixed': False, 'elapsed_seconds': time.monotonic()-started,
        'freeze_sha256': sha(output/'freeze.json')})


if __name__ == '__main__':
    main()

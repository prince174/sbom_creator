"""Bounded JS publisher regression from twelve immutable cached predictions.

No scanners, checkout, source resolver or build-reference evaluator are invoked.
Chalk uses its separately successful R106 diagnostic publication, while the
original R106 failed attempt remains explicitly recorded rather than relabelled.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

from run import ROOT, atomic_json


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def coordinates(document):
    return Counter(json.dumps([component.get(key) for key in ('type', 'group', 'name', 'version', 'purl')],
                              ensure_ascii=True, separators=(',', ':'))
                   for component in document.get('components', []))


def selected_ids(document):
    return sorted(artifact['id'] for artifact in document['artifacts'])


def main():
    output = ROOT/'benchmarks/results/mvp-r107-js-publish-v1'
    if output.exists():
        raise FileExistsError('Preserve every completed and attempted regression')
    previous = ROOT/'benchmarks/results/mvp-r106-v1/javascript'
    chalk = ROOT/'benchmarks/results/chalk-publish-diagnostic-v1'
    cases = []
    for path in sorted(previous.glob('paired-*')):
        original_run = path/'run.json'
        original = json.loads(original_run.read_bytes())
        separate_diagnostic = path.name == 'paired-chalk-v1'
        if separate_diagnostic:
            if original['status'] != 'FAILED' or json.loads((chalk/'run.json').read_bytes())['status'] != 'completed':
                raise ValueError('Expected original Chalk failure and separate diagnostic success')
            baseline = chalk/'analysis'
        else:
            if original['status'] != 'completed':
                raise ValueError('Unexpected incomplete R106 baseline')
            baseline = path/'analysis'
        cases.append({'name': path.name, 'baseline': baseline,
                      'original_run': original_run, 'separate_diagnostic': separate_diagnostic})
    if len(cases) != 12 or len({case['name'] for case in cases}) != 12:
        raise ValueError('Exactly twelve unique cached JavaScript cases are required')
    snapshot = output/'executed-source'
    shutil.copytree(ROOT/'src/sbom_creator', snapshot/'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output/'executed-runner.py')
    syft = ROOT/'.tools/syft/syft.exe'
    names = ('source.syft.json', 'image.syft.json', 'provenance.json', 'selected.syft.json',
             'final.cdx.json', 'os.cdx.json', 'full.cdx.json')
    frozen_inputs = [case['baseline']/name for case in cases for name in names]
    frozen_inputs.extend(case['original_run'] for case in cases)
    atomic_json(output/'freeze.json', {'oracle_read': False, 'fresh_scans': False,
        'fresh_physical_reads': False, 'source_input': False, 'project_execution': False,
        'java_nested_windows': True, 'production_default_changed': False,
        'mode': 'actual publisher with cached raw image/source catalogs and physical evidence',
        'syft_converter_sha256': sha(syft), 'runner_sha256': sha(Path(__file__)),
        'code_sha256': {path.relative_to(snapshot).as_posix(): sha(path)
                       for path in sorted(snapshot.rglob('*')) if path.is_file()},
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in frozen_inputs},
        'original_attempts': [{'name': case['name'], 'original_run': case['original_run'].relative_to(ROOT).as_posix(),
            'baseline': case['baseline'].relative_to(ROOT).as_posix(),
            'separate_chalk_diagnostic': case['separate_diagnostic']} for case in cases]})
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.core import rules_assessor
    from sbom_creator.pipeline import publish_catalogs
    from sbom_creator.validation import validate_cyclonedx

    if not Path(sys.modules['sbom_creator.pipeline'].__file__).is_relative_to(snapshot):
        raise ValueError('Publisher did not import the frozen source snapshot')
    settings = Settings(syft_binary=str(syft), java_backend='disabled', java_nested_windows=True)
    reports, started = [], time.monotonic()
    for case in cases:
        target = output/case['name']
        before = time.monotonic()
        source = json.loads((case['baseline']/'source.syft.json').read_bytes())
        image = json.loads((case['baseline']/'image.syft.json').read_bytes())
        provenance = json.loads((case['baseline']/'provenance.json').read_bytes())
        if source['artifacts'] or provenance.get('request', {}).get('repository_url') is not None:
            raise ValueError('Regression input must remain image-only with empty source')
        summary = publish_catalogs(source, image, target/'analysis', settings, rules_assessor, provenance)
        views = {}
        for view in ('final', 'os', 'full'):
            path = target/'analysis'/(view+'.cdx.json')
            actual = json.loads(path.read_bytes())
            validate_cyclonedx(actual)
            baseline = json.loads((case['baseline']/(view+'.cdx.json')).read_bytes())
            if coordinates(actual) != coordinates(baseline):
                raise ValueError('Publisher component-coordinate regression')
            views[view] = {'coordinates_equal': True, 'component_count': len(actual.get('components', [])),
                           'sha256': sha(path), 'cyclonedx_schema_valid': True}
        selected = selected_ids(json.loads((target/'analysis/selected.syft.json').read_bytes()))
        if selected != selected_ids(json.loads((case['baseline']/'selected.syft.json').read_bytes())):
            raise ValueError('Publisher selected artifact identity regression')
        report = {'name': case['name'], 'status': 'passed', 'oracle_read': False,
            'fresh_scans': False, 'fresh_physical_reads': False, 'source_input': False,
            'elapsed_seconds': time.monotonic()-before, 'views': views, 'selected_artifact_ids_equal': True,
            'summary': summary, 'baseline': case['baseline'].relative_to(ROOT).as_posix(),
            'original_r106_run_status': 'FAILED' if case['separate_diagnostic'] else 'completed',
            'separate_chalk_diagnostic': case['separate_diagnostic'],
            'locking_failure_fixed': False, 'new_accuracy_measurement': False}
        atomic_json(target/'run.json', report)
        reports.append(report)
        print(case['name'], 'publisher parity passed', flush=True)
    for path, digest in json.loads((output/'freeze.json').read_bytes())['input_sha256'].items():
        if sha(ROOT/path) != digest:
            raise ValueError('Frozen cached input changed during regression')
    atomic_json(output/'report.json', {'status': 'passed', 'cases': reports,
        'fresh_scans': False, 'fresh_physical_reads': False, 'oracle_read': False,
        'source_input': False, 'java_nested_windows': True, 'new_accuracy_measurement': False,
        'r106_successful_baselines': 11, 'separate_chalk_diagnostic_baselines': 1,
        'original_chalk_failure_preserved': True, 'locking_failure_fixed': False,
        'views_equal': 36, 'selected_artifact_id_sets_equal': 12,
        'elapsed_seconds': time.monotonic()-started, 'freeze_sha256': sha(output/'freeze.json')})


if __name__ == '__main__':
    main()

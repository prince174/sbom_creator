"""Post-only R106 actual service evaluation with unchanged R105 scoring scopes."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import evaluate_mvp_javascript as javascript
from compare_java_js import all_components, coord
from evaluate_mvp_runtime import (
    CASES,
    evaluate_boot,
    evaluate_reactor,
    macro,
    sha,
    validate_predictions,
)
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import projected, read
from run import ROOT, atomic_json

BASELINE = ROOT / 'benchmarks/results/mvp-image-r105-v2'
SERIAL_BOOT = ROOT / 'benchmarks/results/mvp-image-r105-serial-boot/boot/analysis'


def preflight(output):
    """Validate all attempted predictions before any component oracle is read."""
    marker, freeze = read(output / 'predictions-complete.json'), read(output / 'freeze.json')
    if marker.get('oracle_read') is not False or marker.get('freeze_sha256') != sha(output / 'freeze.json'):
        raise ValueError('Complete no-oracle prediction marker is required')
    if set(marker.get('cases', {}).get('java', [])) != set(CASES):
        raise ValueError('All four fixed Java cases are required')
    if len(marker.get('cases', {}).get('javascript', [])) != 12:
        raise ValueError('All twelve no-lock JavaScript cases are required')
    for language in ('java', 'javascript'):
        if sha(output / language / 'freeze.json') != freeze[language + '_freeze_sha256']:
            raise ValueError('A frozen candidate record changed')
    tools = {'syft': ROOT / '.tools/syft/syft.exe',
             'trivy': ROOT / 'benchmarks/.work/trivy-r34/trivy.exe',
             'crane': ROOT / 'benchmarks/.work/crane-r94/crane.exe'}
    for name, path in tools.items():
        if sha(path) != freeze['tool_sha256'][name]:
            raise ValueError('Scanner binary changed')
    database = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache/java-db/trivy-java.db'
    if sha(database) != freeze['database_sha256']:
        raise ValueError('Pinned scanner database changed')
    requested, java = validate_predictions(output / 'java')
    javascript.OUTPUT = output / 'javascript'
    js = javascript.prepared_outputs()
    if set(requested) != set(marker['cases']['java']) or {row[0] for row in js} != set(marker['cases']['javascript']):
        raise ValueError('Prediction manifests disagree')
    return requested, java


def full_views(analysis):
    if analysis is None:
        return None
    return {view: Counter(coord(c) for c in all_components(read(analysis / (view + '.cdx.json')))
                          if coord(c)) for view in ('final', 'os', 'full')}


def view_regression(current, baseline):
    current_views, baseline_views = full_views(current), full_views(baseline)
    if current_views is None:
        return {'status': 'NO_CURRENT_FINAL', 'baseline': baseline.relative_to(ROOT).as_posix()}
    return {'baseline': baseline.relative_to(ROOT).as_posix(), 'coordinate_multisets': {
        view: {'added': dict(current_views[view] - baseline_views[view]),
               'removed': dict(baseline_views[view] - current_views[view])}
        for view in current_views}}


def attach_regression(case, result, prediction):
    baseline = SERIAL_BOOT if case == 'boot' else BASELINE / case / 'analysis'
    result['r105_final_regression'] = view_regression(prediction['analysis'], baseline)
    if case != 'boot':
        old = read(baseline / 'final.cdx.json')
        new = read(prediction['analysis'] / 'final.cdx.json') if prediction['analysis'] else None
        for row in result['rows']:
            before = projected(old, row['image_prefix'], row['owner'])
            after = projected(new, row['image_prefix'], row['owner']) if new else set()
            row['r105_exact_coordinate_regression'] = {
                'added': sorted(after - before), 'removed': sorted(before - after)}
    if prediction['analysis']:
        audit = prediction['analysis'] / 'image-identity-audit.json'
        if audit.is_file():
            document = read(audit)
            result['resources'] = {key: document.get(key) for key in ('jar_resources', 'layer_resources')}
        result['unknown_counts'] = read(prediction['analysis'] / 'coverage.json')


def evaluate_java(output, requested, predictions):
    reports = {}
    for case in requested:
        folder = ROOT / 'benchmarks/references' / CASES[case]
        result = (evaluate_boot(folder, predictions[case]) if case == 'boot'
                  else evaluate_reactor(folder, predictions[case]))
        prediction, run = predictions[case], predictions[case]['run']
        result.update(status=run['status'], seconds=run.get('elapsed_seconds'),
                      output_sha256=prediction['hashes'], runtime_changed=True,
                      original_build_graph_reproduced=False)
        if prediction['analysis']:
            result['runtime_summary'] = read(prediction['analysis'] / 'summary.json')
            result['java_image_status'] = prediction['provenance']['image'].get('java_image_status')
        attach_regression(case, result, prediction)
        reports[case] = result
    rows = [report.get('components', report.get('components_micro')) for report in reports.values()]
    result = {'mode': 'actual service image-only; no source/commit/reference supplied to analyzer',
              'reports': reports, 'java_components_micro': aggregate(rows),
              'java_components_macro_across_repositories': macro(rows),
              'java_direct': aggregate([report['direct'] for report in reports.values()]),
              'source_input': False, 'fresh_scans': True, 'acceptance': False,
              'runtime_changed': True, 'same_scoring_scopes_as_r105': True,
              'limitations': [
                  'All four cases are disclosed development controls, not independent acceptance',
                  'Native/CycloneDX scope disagreements retain raw deltas and do not become successes',
                  'Reactor owners are module instances, not independent repositories',
                  'Image-only mode does not prove directness or the unknown original CI graph',
                  'Metadata-only JAR misses remain FN; no oracle-dependent component exclusions',
                  'GAV scoring does not establish independently labelled classifier/type accuracy',
                  'Timings include fresh scans but exclude existing local archive registry acquisition',
                  'Peak RSS, hard filesystem quota, and concurrent resource safety are not established']}
    atomic_json(output / 'java/evaluation.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/results/mvp-r106-v1')
    args = parser.parse_args()
    output = args.output.resolve()
    if any((output / name).exists() for name in ('evaluation.json', 'java/evaluation.json', 'javascript/evaluation.json')):
        raise FileExistsError('Preserve completed and partially completed evaluations')
    requested, predictions = preflight(output)
    # Oracle access begins only here, after all 16 invocations and 48 views/attempts.
    java = evaluate_java(output, requested, predictions)
    javascript.main()
    js = read(output / 'javascript/evaluation.json')
    previous = ROOT / 'benchmarks/results/mvp-js-r105-v1'
    js_regression = {row['pair']: view_regression(output / 'javascript' / row['pair'] / 'analysis',
                                                previous / row['pair'] / 'analysis')
                     for row in js['rows'] if row['status'] == 'completed'}
    result = {'mode': 'R106 actual image-only service, Java and JavaScript evaluated separately',
              'java_components_micro': java['java_components_micro'],
              'java_components_macro_across_repositories': java['java_components_macro_across_repositories'],
              'javascript_components_micro': js['components_micro'],
              'javascript_components_macro_positive_projects': js['components_macro_positive_projects'],
              'java_direct': java['java_direct'], 'javascript_direct': js['direct_micro'],
              'operational_status': {
                  'java_completed': sum(r['status'] == 'completed' for r in java['reports'].values()),
                  'java_failed': [case for case, r in java['reports'].items() if r['status'] != 'completed'],
                  'javascript_completed': sum(r['status'] == 'completed' for r in js['rows']),
                  'javascript_failed': [r['pair'] for r in js['rows'] if r['status'] != 'completed'],
                  'failed_empty_cases_are_not_precision_recall_success': True},
              'javascript_r105_final_view_regression': js_regression,
              'runtime_changed': True, 'acceptance': False,
              'reason': 'Disclosed controls and incomplete scope labels cannot establish general independent >90% acceptance',
              'report_sha256': {language: sha(output / language / 'evaluation.json')
                                for language in ('java', 'javascript')}}
    atomic_json(output / 'evaluation.json', result)
    print(json.dumps({key: value for key, value in result.items() if key.endswith('_micro')}))


if __name__ == '__main__':
    main()

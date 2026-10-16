"""Post-only fresh image-only JavaScript scores and stored-output regression."""
import json

from compare_java_js import all_components, coord, graph
from evaluate_mvp_runtime import macro, sha
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import projected, read, reference, versions
from run import ROOT, atomic_json
from score_project_components import metrics

from sbom_creator.validation import validate_cyclonedx

OUTPUT = ROOT / 'benchmarks/results/mvp-js-r105-v1'


def prepared_outputs():
    marker = read(OUTPUT / 'predictions-complete.json')
    if marker.get('oracle_read') is not False or len(marker.get('cases', [])) != 12:
        raise ValueError('All twelve image predictions must finish before evaluation')
    if len(set(marker['cases'])) != 12:
        raise ValueError('Duplicate case names')
    freeze = read(OUTPUT / 'freeze.json')
    snapshot = OUTPUT / freeze['executed_source']
    for name, expected in freeze['code_sha256'].items():
        if sha(snapshot / name) != expected:
            raise ValueError('Executed source snapshot changed')
    if sha(OUTPUT / 'executed-runner.py') != freeze['runner_sha256']:
        raise ValueError('Executed runner snapshot changed')
    prepared = []
    for name in marker['cases']:
        folder = OUTPUT / name
        invocation, run = read(folder / 'invocation.json'), read(folder / 'run.json')
        if invocation.get('repository_url') is not None or invocation.get('commit') is not None:
            raise ValueError('Unexpected source input')
        if invocation.get('oracle_read') is not False or run.get('oracle_read') is not False:
            raise ValueError('Oracle separation missing')
        if sha(ROOT / invocation['archive']) != invocation['archive_sha256']:
            raise ValueError('Image archive input changed')
        analysis = folder / 'analysis'
        if run['status'] == 'completed':
            for view in ('final', 'os', 'full'):
                validate_cyclonedx(read(analysis / (view + '.cdx.json')))
            provenance = read(analysis / 'provenance.json')
            if provenance.get('source_kind') != 'not-provided':
                raise ValueError('Repository inputs unexpectedly provided')
        elif run['status'] == 'FAILED' and not analysis.exists():
            provenance, analysis = None, None
        else:
            raise ValueError('Unfinished or inconsistent prediction')
        prepared.append((name, invocation, run, analysis, provenance))
    return prepared


def main():
    destination = OUTPUT / 'evaluation.json'
    if destination.exists():
        raise FileExistsError('Preserve completed evaluation')
    predictions = prepared_outputs()
    # Reference and prior accuracy output reads begin here, after all 36 views/attempts.
    rows = []
    for name, invocation, run, analysis, provenance in predictions:
        pair = ROOT / 'benchmarks/references' / name
        receipt = read(pair / 'receipt.json')
        if receipt.get('reference_hashes'):
            reference(pair)
        elif sha(pair / 'sbom.json') != receipt['reference_sha256']:
            raise ValueError('Immutable reference changed')
        namespace = invocation['namespace']
        old_folder = ROOT / 'benchmarks/results' / namespace / name
        binding = read(old_folder / 'binding-proof.json')
        expected_config = binding.get('image_binding', binding.get('binding'))['config_digest']
        if provenance and provenance['image']['image_config_digest'] != expected_config:
            raise ValueError('Derivative no-lock image config binding differs')
        bom = read(pair / 'sbom.json')
        owner = coord(bom['metadata']['component'])
        actual = projected(read(analysis / 'final.cdx.json'), '/app/', owner) if analysis else set()
        expected = {coord(c) for c in all_components(bom) if coord(c)} - {owner}
        expected_direct = graph(bom, owner)
        if expected_direct is None:
            raise ValueError('Reference direct graph is unlabelled')
        previous_analysis = ROOT / 'benchmarks/.work' / namespace / name / 'analysis'
        previous = projected(read(previous_analysis / 'final.cdx.json'), '/app/', owner)
        previous_report = read(old_folder / 'report.json')
        if previous_report['direct'].get('result_sha256', sha(previous_analysis / 'final.cdx.json')) != sha(previous_analysis / 'final.cdx.json'):
            raise ValueError('Stored baseline final changed')
        result = {'project': receipt['project'], 'pair': name, 'status': run['status'],
                  'seconds': run['elapsed_seconds'], 'components': metrics(actual, expected),
                  'versions': versions(actual, expected), 'count_delta': len(actual) - len(expected),
                  'missing': sorted(expected - actual), 'extra': sorted(actual - expected),
                  'direct': metrics(set(), expected_direct), 'direct_status': 'UNKNOWN_NO_SOURCE_INPUT',
                  'component_regression': {'added': sorted(actual - previous),
                                           'removed': sorted(previous - actual),
                                           'baseline': metrics(previous, expected)},
                  'scoring_scope': '/app/; root application excluded; Node/npm platform retained separately',
                  'reference_sha256': sha(pair / 'sbom.json')}
        if analysis:
            result['output_sha256'] = {view: sha(analysis / (view + '.cdx.json')) for view in ('final', 'os', 'full')}
            result['runtime_summary'] = read(analysis / 'summary.json')
        rows.append(result)
    positive = [r['components'] for r in rows if r['components']['reference']]
    report = {'runtime_changed': True, 'fresh_scans': True, 'source_input': False,
              'mode': 'actual image-only service; no project source/image lockfiles',
              'projects': len(rows), 'positive_component_projects': len(positive),
              'components_micro': aggregate([r['components'] for r in rows]),
              'components_macro_positive_projects': macro(positive),
              'direct_micro': aggregate([r['direct'] for r in rows]),
              'direct_status': 'UNKNOWN_NO_SOURCE_INPUT',
              'components_exact_identity_regression': {
                  'projects_with_added_components': sum(bool(r['component_regression']['added']) for r in rows),
                  'projects_with_removed_components': sum(bool(r['component_regression']['removed']) for r in rows)},
              'rows': rows, 'acceptance': False,
              'limitations': ['Disclosed no-lock derivative fixtures, not fresh independent general ownership acceptance',
                             'Fixed /app scoring scope is an evaluation fixture convention, not a reference-based filter',
                             'Empty roots excluded from positive macro, never counted as precision/recall success',
                             'Full non-OS image inventory is retained; test fixtures remain extra project components',
                             'Image-only mode does not prove directness; all known reference direct edges counted FN']}
    atomic_json(destination, report)
    print(json.dumps({'components': report['components_micro'], 'direct': report['direct_micro'],
                      'regression': report['components_exact_identity_regression']}))


if __name__ == '__main__':
    main()

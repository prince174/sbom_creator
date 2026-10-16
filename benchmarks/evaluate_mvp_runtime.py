"""Post-only evaluation of actual service output, never raw scanner inventory.

The prediction runner must write predictions-complete.json only after every
requested invocation has completed. This script cannot run a classifier or read
reference labels before it has validated the complete prediction set.
"""
import argparse
import hashlib
import json
from pathlib import Path

from compare_java_js import all_components, coord
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import projected, read, reference, versions
from run import ROOT, atomic_json
from score_project_components import metrics

from sbom_creator.validation import validate_cyclonedx

CASES = {
    'boot': 'paired-spring-petclinic-v1',
    'javalin': 'paired-javalin-reactor-v1',
    'dropwizard': 'paired-dropwizard-reactor-v1',
    'microservices': 'paired-petclinic-microservices-r104',
}
VIEWS = ('final', 'os', 'full')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def macro(rows):
    """Undefined/empty rows do not become perfect macro examples."""
    return {key: (sum(r[key] for r in rows if r[key] is not None)
                  / len([r for r in rows if r[key] is not None])
                  if any(r[key] is not None for r in rows) else None)
            for key in ('precision', 'recall', 'f1')}


def validate_predictions(output):
    marker = read(output / 'predictions-complete.json')
    if marker.get('oracle_read') is not False or not marker.get('cases'):
        raise ValueError('Explicit post-prediction marker is required')
    requested = marker['cases']
    if not isinstance(requested, list) or len(requested) != len(set(requested)):
        raise ValueError('Prediction case names must be unique')
    if any(case not in CASES for case in requested):
        raise ValueError('Unsupported evaluation case')
    freeze_path = output / 'candidate-freeze.json'
    if not freeze_path.exists():
        freeze_path = output / 'freeze.json'
    freeze = read(freeze_path)
    for group in ('code_sha256', 'input_sha256'):
        for name, expected in freeze.get(group, {}).items():
            if sha(ROOT / name) != expected:
                snapshot = output / 'executed-source' / name
                if not snapshot.is_file() or sha(snapshot) != expected:
                    raise ValueError('Frozen candidate/input changed: ' + name)
    prepared = {}
    for case in requested:
        folder = output / case
        run = read(folder / 'run.json')
        if run.get('oracle_read') is not False:
            raise ValueError('Unconfirmed oracle separation: ' + case)
        analysis = folder / 'analysis'
        invocation = read(folder / 'invocation.json')
        if invocation.get('oracle_read') is not False or invocation.get('repository_url') is not None or invocation.get('commit') is not None:
            raise ValueError('Image-only invocation must not carry source/reference inputs')
        archive = ROOT / 'benchmarks/.work' / CASES[case] / 'image.tar'
        if sha(archive) != invocation.get('archive_sha256'):
            raise ValueError('Prediction archive bytes changed')
        if run.get('status') in ('failed', 'FAILED'):
            if analysis.exists():
                raise ValueError('Failed prediction cannot carry a published analysis')
            prepared[case] = {'run': run, 'analysis': None, 'hashes': {}}
            continue
        if run.get('status') not in ('succeeded', 'completed'):
            raise ValueError('Unfinished prediction: ' + case)
        hashes = {}
        for view in VIEWS:
            path = analysis / (view + '.cdx.json')
            validate_cyclonedx(read(path))
            hashes[view] = sha(path)
        if read(analysis / 'summary.json').get('status') != 'succeeded':
            raise ValueError('Service did not publish success')
        provenance = read(analysis / 'provenance.json')
        if provenance.get('source_kind') != 'not-provided':
            raise ValueError('Image-only evaluation must not silently consume repository inputs')
        prepared[case] = {'run': run, 'analysis': analysis, 'hashes': hashes,
                          'provenance': provenance}
    return requested, prepared


def bound_receipt(folder, prepared):
    receipt = reference(folder)
    if prepared['analysis'] is None:
        return receipt
    expected = receipt.get('image_binding', {}).get('config_digest')
    if expected is None:
        expected = receipt.get('image', {}).get('config_digest')
    observed = prepared['provenance'].get('image', {}).get('image_config_digest')
    if expected is None or expected != observed:
        raise ValueError('Runtime final is not bound to the reference image config')
    return receipt


def native_set(document):
    pending, resolved = list(document.get('children', [])), set()
    for node in pending:
        resolved.add(f"pkg:maven/{node['groupId']}/{node['artifactId']}@{node['version']}")
        pending.extend(node.get('children', []))
    return resolved


def component_row(actual, expected):
    return {'components': metrics(actual, expected), 'versions': versions(actual, expected),
            'count_delta': len(actual) - len(expected), 'missing': sorted(expected - actual),
            'extra': sorted(actual - expected)}


def evaluate_boot(folder, prediction):
    receipt = bound_receipt(folder, prediction)
    labels_path = ROOT / 'benchmarks/results/boot-packaging-labels-v3/report.json'
    labels = read(labels_path)
    if labels['commit'] != receipt['commit'] or labels['unlabelled_build_reference']:
        raise ValueError('Packaging reference is unbound or incomplete')
    owner = coord(read(folder / 'sbom.json')['metadata']['component'])
    actual = (projected(read(prediction['analysis'] / 'final.cdx.json'), '/application/', owner)
              if prediction['analysis'] else set())
    expected = set(labels['packaged'])
    return {**component_row(actual, expected), 'scored_owners': 1, 'scope_unknown_owners': 0,
            'scope': 'known SHA256-labelled packaged dependencies under /application/',
            'packaging_labels_sha256': sha(labels_path),
            'packaging_unknown_charged_fp': len(labels['unknown_packaged']),
            'direct': metrics(set(), set(labels['root_direct_build'])),
            'direct_status': 'UNKNOWN_NO_SOURCE_INPUT'}


def evaluate_reactor(folder, prediction):
    bound_receipt(folder, prediction)
    final = read(prediction['analysis'] / 'final.cdx.json') if prediction['analysis'] else None
    rows = []
    for label in read(folder / 'module-labels.json'):
        if not label['image_prefix']:
            continue
        module = folder / 'modules' / ('root' if label['path'] == '.' else label['path'])
        bom, native = read(module / 'sbom.json'), read(module / 'dependency-tree.json')
        owner = coord(bom['metadata']['component'])
        expected = {coord(c) for c in all_components(bom) if coord(c)} - {owner}
        actual = projected(final, label['image_prefix'], owner) if final else set()
        agreed = expected == native_set(native)
        raw = component_row(actual, expected)
        rows.append({'path': label['path'], 'owner': owner, 'image_prefix': label['image_prefix'],
                     'scope': 'NATIVE_CDX_AGREEMENT' if agreed else 'UNKNOWN_NATIVE_CDX_TRANSITIVE_MISMATCH',
                     **{k: v if agreed else None for k, v in raw.items()},
                     'raw_build_reference_delta': raw,
                     'direct': metrics(set(), {tuple(edge) for edge in label['direct']}),
                     'direct_status': 'UNKNOWN_NO_SOURCE_INPUT',
                     'qualifier_evaluation': label.get('qualifier_evaluation', 'GAV_ONLY')})
    scored = [r for r in rows if r['components'] is not None]
    return {'rows': rows, 'components_micro': aggregate([r['components'] for r in scored]),
            'components_macro_across_modules': macro([r['components'] for r in scored]),
            'scored_owners': len(scored), 'scope_unknown_owners': len(rows) - len(scored),
            'direct': aggregate([r['direct'] for r in rows]),
            'direct_status': 'UNKNOWN_NO_SOURCE_INPUT',
            'scope': 'per-module dependency trees agree with CycloneDX component set; fixed image paths'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/results/mvp-image-r105-v2')
    args = parser.parse_args()
    output = args.output.resolve()
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve completed evaluation')
    requested, predictions = validate_predictions(output)
    # The first oracle read occurs below, after all service predictions are complete.
    reports = {}
    for case in requested:
        folder = ROOT / 'benchmarks/references' / CASES[case]
        result = evaluate_boot(folder, predictions[case]) if case == 'boot' else evaluate_reactor(folder, predictions[case])
        run = predictions[case]['run']
        result.update(status=run['status'], seconds=run.get('seconds', run.get('elapsed_seconds')),
                      output_sha256=predictions[case]['hashes'], runtime_changed=True,
                      original_build_graph_reproduced=False)
        if predictions[case]['analysis']:
            result['runtime_summary'] = read(predictions[case]['analysis'] / 'summary.json')
            result['java_image_status'] = predictions[case]['provenance']['image'].get('java_image_status')
        reports[case] = result
    component_rows = [r.get('components', r.get('components_micro')) for r in reports.values()]
    result = {'mode': 'actual service image-only; no source/commit/reference supplied to analyzer',
              'reports': reports, 'java_components_micro': aggregate(component_rows),
              'java_components_macro_across_repositories': macro(component_rows),
              'java_direct': aggregate([r['direct'] for r in reports.values()]),
              'acceptance': False, 'runtime_changed': True,
              'limitations': ['Disclosed development cases; not fresh independent production acceptance',
                             'Reactor owner instances are not independent repositories',
                             'Unknown owner scopes retain raw component deltas and are not scored as successes',
                             'Image-only mode does not establish source directness or the original CI graph',
                             'Empty metadata-only JARs remain missing; no oracle-dependent exclusion',
                             'PURL classifier/type qualifiers are not independently labelled by GAV comparison',
                             'Physical payload presence does not prove execution; no universal accuracy guarantee']}
    atomic_json(output / 'evaluation.json', result)
    print(json.dumps({case: r.get('components', r.get('components_micro')) for case, r in reports.items()}))


if __name__ == '__main__':
    main()

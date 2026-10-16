"""Post-only component/direct comparison of complete final outputs."""
import json

from compare_java_js import all_components, coord
from evaluate_trivy_payload_bridge import projected, read, reference, versions
from run import ROOT, atomic_json
from score_project_components import metrics


def aggregate(rows):
    tp, fp, fn = (sum(row[key] for row in rows) for key in ('tp', 'fp', 'fn'))
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': tp/(tp+fp) if tp+fp else None,
            'recall': tp/(tp+fn) if tp+fn else None,
            'f1': 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}


def main():
    output = ROOT / 'benchmarks/results/seekable-payload-v3'
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve evaluation')
    for case in ('boot', 'javalin', 'dropwizard'):
        run = read(output / case / 'run.json')
        if not run['three_views_valid'] or run['oracle_read']:
            raise ValueError('Predictions incomplete')
    # Oracle reads begin only after all nine final/os/full views exist.
    boot = ROOT / 'benchmarks/references/paired-spring-petclinic-v1'
    reference(boot)
    labels = read(ROOT / 'benchmarks/results/boot-packaging-labels-v3/report.json')
    owner = coord(read(boot / 'sbom.json')['metadata']['component'])
    actual = projected(read(output / 'boot/final.cdx.json'), '/application/', owner)
    expected = set(labels['packaged'])
    reports = {'boot': {'components': metrics(actual, expected), 'versions': versions(actual, expected),
                        'count_delta': len(actual)-len(expected), 'missing': sorted(expected-actual),
                        'extra': sorted(actual-expected), 'direct_unknown_fn': len(labels['root_direct_build'])}}
    for case, pair in [('javalin', 'paired-javalin-reactor-v1'), ('dropwizard', 'paired-dropwizard-reactor-v1')]:
        folder = ROOT / 'benchmarks/references' / pair
        reference(folder)
        final = read(output / case / 'final.cdx.json')
        rows = []
        for label in read(folder / 'module-labels.json'):
            if not label['image_prefix']:
                continue
            path = folder / 'modules' / label['path']
            bom, native = read(path / 'sbom.json'), read(path / 'dependency-tree.json')
            owner = coord(bom['metadata']['component'])
            expected = {coord(c) for c in all_components(bom) if coord(c)}-{owner}
            actual = projected(final, label['image_prefix'], owner)
            pending, resolved = list(native.get('children', [])), set()
            for node in pending:
                resolved.add(f"pkg:maven/{node['groupId']}/{node['artifactId']}@{node['version']}")
                pending.extend(node.get('children', []))
            agreed = expected == resolved
            rows.append({'path': label['path'], 'scope_agreed': agreed,
                         'components': metrics(actual, expected) if agreed else None,
                         'raw_build_delta': metrics(actual, expected),
                         'versions': versions(actual, expected) if agreed else None,
                         'count_delta': len(actual)-len(expected), 'missing': sorted(expected-actual),
                         'extra': sorted(actual-expected), 'direct_unknown_fn': len(label['direct'])})
        scored = [row['components'] for row in rows if row['scope_agreed']]
        reports[case] = {'rows': rows, 'components_micro': aggregate(scored),
                         'components_macro_across_modules': {key: sum(r[key] or 0 for r in scored)/len(scored)
                         for key in ('precision', 'recall', 'f1')},
                         'scored_owners': len(scored), 'scope_unknown_owners': len(rows)-len(scored),
                         'direct_unknown_fn': sum(r['direct_unknown_fn'] for r in rows)}
    atomic_json(output / 'evaluation.json', {'runtime_changed': False, 'acceptance': False,
                'partition': 'disclosed_development', 'reports': reports,
                'limitations': ['Actual published final, never raw inventory substituted',
                               'Owner-level counts are not independent project counts',
                               'Source-owner/direct graphs not integrated; all known direct UNKNOWN counted FN',
                               'Unknown native/CDX scope owners retain raw deltas; no language-wide extrapolation']})
    print(json.dumps({key: value.get('components', value.get('components_micro')) for key, value in reports.items()}))


if __name__ == '__main__':
    main()

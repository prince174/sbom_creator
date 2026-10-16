"""Post-only, scope-aware report; a completed empty final is measured as misses."""
import json

from compare_java_js import all_components, coord
from evaluate_trivy_payload_bridge import projected, read, reference, versions
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    output = ROOT / 'benchmarks/results/cached-dropwizard-evidence-v3'
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve evaluation')
    run = read(output / 'run.json')
    if not run['three_views_valid'] or run['oracle_read']:
        raise ValueError('Prediction not complete')
    final = read(output / 'final.cdx.json')
    # No oracle is read until all three views have been published.
    pair = ROOT / 'benchmarks/references/paired-dropwizard-reactor-v1'
    receipt = reference(pair)
    rows = []
    for label in read(pair / 'module-labels.json'):
        if not label['image_prefix']:
            continue
        folder = pair / 'modules' / label['path']
        bom = read(folder / 'sbom.json')
        owner = coord(bom['metadata']['component'])
        expected = {coord(c) for c in all_components(bom) if coord(c)} - {owner}
        actual = projected(final, label['image_prefix'], owner)
        native = read(folder / 'dependency-tree.json')
        pending, resolved = list(native.get('children', [])), set()
        for node in pending:
            resolved.add(f"pkg:maven/{node['groupId']}/{node['artifactId']}@{node['version']}")
            pending.extend(node.get('children', []))
        agreed = expected == resolved
        rows.append({'path': label['path'], 'owner': owner, 'scope_agreed': agreed,
                     'components': metrics(actual, expected) if agreed else None,
                     'raw_build_delta': metrics(actual, expected),
                     'versions': versions(actual, expected) if agreed else None,
                     'count_delta': len(actual) - len(expected),
                     'missing': sorted(expected - actual), 'extra': sorted(actual - expected),
                     'direct_unknown_fn': len(label['direct'])})
    scored = [row['components'] for row in rows if row['scope_agreed']]
    tp, fp, fn = (sum(row[key] for row in scored) for key in ('tp', 'fp', 'fn'))
    micro = {'tp': tp, 'fp': fp, 'fn': fn, 'precision': tp/(tp+fp) if tp+fp else None,
             'recall': tp/(tp+fn) if tp+fn else None, 'f1': 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}
    macro = {key: (sum(row[key] for row in scored if row[key] is not None) /
                   sum(row[key] is not None for row in scored)) if any(row[key] is not None for row in scored)
             else None for key in ('precision', 'recall', 'f1')}
    atomic_json(output / 'evaluation.json', {'runtime_changed': False, 'acceptance': False,
                'partition': 'disclosed_resource_development', 'project': receipt['project'],
                'rows': rows, 'components_micro': micro, 'components_macro_across_module_owners': macro,
                'scored_owners': len(scored), 'scope_unknown_owners': len(rows)-len(scored),
                'direct_known_unknown_fn': sum(row['direct_unknown_fn'] for row in rows),
                'limits_increased': False,
                'limitations': ['Resource completion, not an accuracy improvement',
                               'Whole layer remains over budget, so no payload can be confirmed',
                               'Native/CDX transitive disagreement kept UNKNOWN with raw delta visible',
                               'One repository, not 34 independent projects; source graph integration absent']})
    print(json.dumps({'micro': micro, 'scored': len(scored), 'scope_unknown': len(rows)-len(scored)}))


if __name__ == '__main__':
    main()

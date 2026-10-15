"""Fixture-scope component baseline, separate from whole-image inventory."""
import json

from compare_java_js import all_components, coord
from run import ROOT, atomic_json


def metrics(actual, expected):
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'predicted': len(actual), 'reference': len(expected),
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def main():
    rows = []
    selected = set(json.loads((ROOT / 'benchmarks/java-js-twenty-split.json').read_bytes())['development_projects'])
    for receipt_path in sorted((ROOT / 'benchmarks/references').glob('paired-*/receipt.json')):
        receipt = json.loads(receipt_path.read_bytes())
        project = receipt.get('project', '')
        if project not in selected:
            continue
        pair = receipt_path.parent.name
        work = ROOT / 'benchmarks/.work' / pair
        image = json.loads((work / 'analysis/image.syft.json').read_bytes())
        final = json.loads((work / 'analysis/final.cdx.json').read_bytes())
        # Fixed fixture paths from our build recipes, not oracle-discovered paths.
        prefix = '/app/' if project.startswith('javascript-') else '/application/'
        projected = {coord(a) for a in image['artifacts'] if coord(a) and
                     any(p.get('path', '').startswith(prefix) for p in a.get('locations', []))}
        all_packages = {coord(c) for c in all_components(final) if coord(c)}
        # Oracle is opened after prediction. Root application excluded consistently.
        reference = json.loads((receipt_path.parent / 'sbom.json').read_bytes())
        owner = coord(reference.get('metadata', {}).get('component', {}))
        expected = {coord(c) for c in all_components(reference) if coord(c)} - {owner}
        projected.discard(owner)
        all_packages.discard(owner)
        rows.append({'project': project, 'fixture_scope': prefix, 'project_components': metrics(projected, expected),
                     'unscoped_final_count': len(all_packages), 'excluded_platform_or_other_count': len(all_packages - projected),
                     'missing': sorted(expected - projected), 'extra': sorted(projected - expected)})
    atomic_json(ROOT / 'docs/project-components-baseline-v1.json', {'rows': rows,
                'runtime_changed': False, 'limitation': 'Known fixture installation paths only; not a general production ownership classifier. No direct-edge claim.'})
    print(json.dumps([{k: v for k, v in r.items() if k not in ('missing', 'extra')} for r in rows]))


if __name__ == '__main__':
    main()

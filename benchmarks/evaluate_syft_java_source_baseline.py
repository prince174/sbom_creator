import json

from paired_express import root_dependencies, sha
from run import ROOT, atomic_json
from syft_java_source_baseline import extract


def main():
    rows = []
    for name, module in [('gson', 'gson/pom.xml'), ('commons-text', 'pom.xml')]:
        work = ROOT / 'benchmarks/.work' / ('paired-' + name + '-v1')
        out = ROOT / 'benchmarks/references' / ('paired-' + name + '-v1')
        catalog = json.loads((work / 'analysis/source.syft.json').read_bytes())
        prediction = extract(catalog, module)
        receipt = json.loads((out / 'receipt.json').read_bytes())
        if sha(work / 'analysis/source.syft.json') != receipt['outputs']['source.syft.json']:
            raise ValueError('Source catalog changed')
        if sha(out / 'sbom.json') != receipt['reference_hashes']['sbom.json']:
            raise ValueError('Reference changed')
        bom = json.loads((out / 'sbom.json').read_bytes())
        refs = root_dependencies(bom)
        expected = {(c.get('group'), c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
        comparisons = {}
        for mode in ('raw', 'explicit_scope_filter'):
            selected = [r for r in prediction['rows'] if mode == 'raw' or r['retained_by_explicit_scope_filter']]
            coordinates = {tuple(r['coordinate']) for r in selected}
            comparisons[mode] = {'rows': len(selected), 'coordinate_matches': len(coordinates & expected),
                                 'outside_reference_coordinates': len(coordinates - expected),
                                 'missing_reference_coordinates': len(expected - coordinates),
                                 'unspecified_scope_rows': sum(r['raw_scope'] is None for r in selected)}
        rows.append({'project': name, 'syft_version': catalog.get('descriptor', {}).get('version'),
                     'source_sha256': sha(work / 'analysis/source.syft.json'), 'prediction': prediction,
                     'comparisons': comparisons})
    report = {'experiment': 'R31', 'partition': 'two Java development pairs', 'rows': rows,
              'runtime_changed': False, 'holdout_read': False, 'direct_precision': None, 'direct_recall': None,
              'limitation': 'Raw scope is not effective scope. Outside runtime reference is not automatically a scanner error.'}
    atomic_json(ROOT / 'docs/syft-java-source-baseline-v1.json', report)
    print(json.dumps([{k: v for k, v in r.items() if k != 'prediction'} for r in rows]))


if __name__ == '__main__':
    main()

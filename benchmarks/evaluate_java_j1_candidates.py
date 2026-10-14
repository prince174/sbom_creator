"""Two development pairs; candidate agreement is not direct accuracy."""
import json

from java_j1_candidates import predict
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json


def main():
    rows = []
    for name, module, paths in [('gson', 'gson/pom.xml', ['pom.xml', 'gson/pom.xml']),
                                ('commons-text', 'pom.xml', ['pom.xml'])]:
        work = ROOT / 'benchmarks/.work' / ('paired-' + name + '-v1')
        out = ROOT / 'benchmarks/references' / ('paired-' + name + '-v1')
        blobs = {p: (work / 'src' / p).read_bytes() for p in paths}
        source = json.loads((work / 'analysis/source.syft.json').read_bytes())
        image = json.loads((work / 'analysis/image.syft.json').read_bytes())
        prediction = predict(blobs, module, source, image)
        receipt = json.loads((out / 'receipt.json').read_bytes())
        for file in ('source.syft.json', 'image.syft.json'):
            if sha(work / 'analysis' / file) != receipt['outputs'][file]:
                raise ValueError('Catalog changed')
        for path in paths:
            ref = 'parent-pom.xml' if name == 'gson' and path == 'pom.xml' else 'pom.xml'
            if sha(work / 'src' / path) != receipt['reference_hashes'][ref]:
                raise ValueError('Source changed')
        if sha(out / 'sbom.json') != receipt['reference_hashes']['sbom.json']:
            raise ValueError('Reference changed')
        bom = json.loads((out / 'sbom.json').read_bytes())
        direct = root_dependencies(bom)
        expected = {(c.get('group'), c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in direct}
        actual = {tuple(c['dependency']) for c in prediction['candidates']}
        rows.append({'project': name, 'receipt_sha256': sha(out / 'receipt.json'), 'prediction': prediction,
                     'candidate_tp': len(actual & expected), 'candidate_fp': len(actual - expected),
                     'reference_edges_without_candidate': len(expected - actual), 'reference_edges': len(expected)})
    files = ['java_j1_candidates.py', 'java_local_management.py', 'java_local_parent.py',
             'java_profile_impact.py', 'java_gav_evidence.py', 'audit_maven_declarations.py']
    report = {'experiment': 'R30', 'partition': 'two development pairs, not holdout', 'rows': rows,
              'candidate_reference_coverage': sum(r['candidate_tp'] for r in rows) / sum(r['reference_edges'] for r in rows),
              'direct_precision': None, 'direct_recall': None, 'runtime_changed': False,
              'frozen_source_hashes': {f: sha(ROOT / 'benchmarks' / f) for f in files},
              'limitation': 'Provisional candidate agreement only. Whole-model UNKNOWN is not zero unknowns.'}
    atomic_json(ROOT / 'docs/java-j1-candidates-v1.json', report)
    print(json.dumps({'rows': [{k: v for k, v in r.items() if k != 'prediction'} for r in rows],
                      'candidate_reference_coverage': report['candidate_reference_coverage']}))


if __name__ == '__main__':
    main()

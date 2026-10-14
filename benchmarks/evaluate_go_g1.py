import json

from go_g1_candidates import predict
from paired_express import root_dependencies, sha
from paired_hey import COMMIT, OUT, WORK
from run import ROOT, atomic_json


def main():
    image = json.loads((WORK / 'analysis/image.syft.json').read_bytes())
    prediction = predict((WORK / 'src/go.mod').read_bytes(), image, COMMIT)
    receipt = json.loads((OUT / 'receipt.json').read_bytes())
    if sha(WORK / 'src/go.mod') != receipt['reference_hashes']['go.mod'] or sha(WORK / 'analysis/image.syft.json') != receipt['outputs']['image.syft.json']:
        raise ValueError('Inputs changed')
    if sha(OUT / 'sbom.json') != receipt['reference_hashes']['sbom.json']:
        raise ValueError('Reference changed')
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    refs = root_dependencies(bom)
    expected = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
    actual = {(c['name'], c['version']) for c in prediction['candidates']}
    report = {'experiment': 'R37', 'partition': 'hey development only', 'prediction': prediction,
              'candidate_matches': len(actual & expected), 'extra_candidates': len(actual - expected),
              'reference_edges_without_candidate': len(expected - actual),
              'direct_precision': None, 'direct_recall': None, 'runtime_changed': False,
              'classifier_sha256': sha(ROOT / 'benchmarks/go_g1_candidates.py'),
              'limitation': 'One declared binary candidate; import directness not proven from analyzer inputs'}
    atomic_json(ROOT / 'docs/go-g1-candidates-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

"""Independent-process resource witness replay and explicit producer checks."""
import hashlib
import json

from replay_trivy_payload_bridge import CASES
from run import ROOT, atomic_json
from trivy_only_payload import CATALOGER, supplement


def read(path):
    return json.loads(path.read_bytes())


def main():
    output = ROOT / 'benchmarks/results/trivy-only-payload-v1'
    if (output / 'repeat.json').exists():
        raise FileExistsError('Preserve completed replay')
    freeze = read(output / 'candidate-freeze.json')
    for name, expected in {**freeze['code_sha256'], **freeze['input_sha256']}.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
    rows = []
    for case, (_, pair, old_analysis, witness_name, peer_name) in CASES.items():
        work = ROOT / 'benchmarks/.work' / pair
        image = read(work / old_analysis / 'image.syft.json')
        peer = read(ROOT / 'benchmarks/results' / peer_name)
        witnesses = read(ROOT / 'benchmarks/results' / witness_name)
        result, evidence, audit = supplement(image, peer, witnesses, work / 'image.tar')
        previous = work / 'analysis-trivy-only-payload-v1'
        assert result == read(previous / 'image.syft.json')
        assert evidence == read(previous / 'provenance.json')['image']['payload_evidence']
        assert json.loads(json.dumps(audit)) == read(output / case / 'supplement.json')
        provenance_checks = []
        for row in audit['supplemental']:
            if row['status'] != 'CORROBORATED_TRIVY_ONLY':
                continue
            for view in ('final', 'full'):
                component = next(c for c in read(output / case / (view + '.cdx.json'))['components']
                                 if c.get('purl') == row['identity'])
                producers = [p['value'] for p in component.get('properties', [])
                             if p.get('name') == 'syft:package:foundBy']
                assert producers == [CATALOGER]
                provenance_checks.append({'view': view, 'purl': row['identity'], 'producer': producers[0]})
        rows.append({'case': case, 'adapted_catalog_exact': True, 'audit_and_payload_exact': True,
                     'exported_producer_verified': provenance_checks})
    atomic_json(output / 'repeat.json', {'status': 'PASSED', 'oracle_read': False, 'rows': rows,
                'mode': 'Fresh bounded physical reads, cached passive engine catalogs; no end-to-end scan timing claim'})
    print(json.dumps({'status': 'PASSED', 'rows': rows}))


if __name__ == '__main__':
    main()

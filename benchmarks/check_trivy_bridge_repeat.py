"""Verify deterministic adapter replay without reopening any build oracle."""
import hashlib
import json

from replay_trivy_payload_bridge import CASES
from run import ROOT, atomic_json
from trivy_payload_bridge import bridge


def read(path):
    return json.loads(path.read_bytes())


def main():
    output = ROOT / 'benchmarks/results/trivy-payload-bridge-v1'
    if (output / 'repeat.json').exists():
        raise FileExistsError('Preserve completed check')
    frozen = read(output / 'candidate-freeze.json')
    for name, expected in {**frozen['code_sha256'], **frozen['input_sha256']}.items():
        with (ROOT / name).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected
    rows = []
    for key, (_, pair, original_name, witness_name, peer_name) in CASES.items():
        work = ROOT / 'benchmarks/.work' / pair
        image = read(work / original_name / 'image.syft.json')
        peer = read(ROOT / 'benchmarks/results' / peer_name)
        assert image['descriptor']['version'] == '1.51.1'
        assert [(tool['name'], tool['version']) for tool in peer['metadata']['tools']['components']] == [('trivy', '0.75.0')]
        witnesses = read(ROOT / 'benchmarks/results' / witness_name)
        result, evidence, audit = bridge(image, peer, witnesses)
        previous = work / 'analysis-trivy-payload-bridge-v1'
        assert result == read(previous / 'image.syft.json')
        assert evidence == read(previous / 'provenance.json')['image']['payload_evidence']
        assert json.loads(json.dumps(audit)) == read(output / key / 'bridge.json')
        rows.append({'case': key, 'artifact_count': len(result['artifacts']),
                     'adapted_catalog_exact': True, 'binding_and_payload_exact': True,
                     'audit_exact': True, 'producer_versions_verified': True})
    atomic_json(output / 'repeat.json', {'status': 'PASSED', 'rows': rows, 'oracle_read': False,
                'mode': 'Independent process deterministic adapter replay; no network/scanner timing claim'})
    print(json.dumps({'status': 'PASSED', 'rows': rows}))


if __name__ == '__main__':
    main()

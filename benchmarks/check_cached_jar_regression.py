"""Known-corpus physical witness and adapter equality; no reference labels."""
import hashlib
import json
from unittest.mock import patch

import trivy_only_payload
from cached_jar_evidence import JarFiles
from replay_trivy_payload_bridge import CASES
from run import ROOT, atomic_json


def main():
    output = ROOT / 'benchmarks/results/cached-jar-regression-v2'
    if output.exists():
        raise FileExistsError('Preserve previous attempt')
    reports = []
    candidate = hashlib.sha256((ROOT / 'benchmarks/cached_jar_evidence.py').read_bytes()).hexdigest()
    for case, (_, pair, previous_name, witness_name, peer_name) in CASES.items():
        work = ROOT / 'benchmarks/.work' / pair
        image = json.loads((work / previous_name / 'image.syft.json').read_bytes())
        expected = json.loads((ROOT / 'benchmarks/results' / witness_name).read_bytes())
        files = JarFiles(work / 'image.tar', image)
        try:
            for artifact in image['artifacts']:
                if artifact.get('foundBy') != 'java-archive-cataloger':
                    continue
                try:
                    witness = files.witness(artifact)
                    error = None
                except (ValueError, KeyError, OSError, RuntimeError) as problem:
                    witness, error = None, type(problem).__name__
                old = expected[artifact['id']]
                assert witness == old['path'] and error == old['error_type']
        finally:
            files.close()
        peer = json.loads((ROOT / 'benchmarks/results' / peer_name).read_bytes())
        with patch.object(trivy_only_payload, 'JarFiles', JarFiles):
            adapted, evidence, audit = trivy_only_payload.supplement(image, peer, expected, work / 'image.tar')
        prior = ROOT / 'benchmarks/results/trivy-only-payload-v1' / case
        old_audit = json.loads((prior / 'supplement.json').read_bytes())
        audit.pop('resource_counters')
        old_audit.pop('resource_counters')
        assert json.loads(json.dumps(audit)) == old_audit
        previous = work / 'analysis-trivy-only-payload-v1'
        assert adapted == json.loads((previous / 'image.syft.json').read_bytes())
        assert evidence == json.loads((previous / 'provenance.json').read_bytes())['image']['payload_evidence']
        reports.append({'case': case, 'witnesses_identical': True, 'catalog_evidence_audit_identical': True,
                        'stats': files.stats})
    atomic_json(output / 'report.json', {'oracle_read': False, 'runtime_changed': False,
                'candidate_sha256': candidate, 'cases': reports})
    print(json.dumps(reports))


if __name__ == '__main__':
    main()

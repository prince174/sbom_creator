"""Explicit-producer candidate replay; never reads evaluation labels."""
import copy
import hashlib
import json
import shutil
import subprocess
import time
from unittest.mock import patch

from replay_trivy_payload_bridge import CASES
from run import ROOT, atomic_json
from trivy_only_payload import CATALOGER, supplement

from sbom_creator import core
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import publish_catalogs, rules_assessor
from sbom_creator.validation import validate_cyclonedx


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    output = ROOT / 'benchmarks/results/trivy-only-payload-v1'
    if output.exists():
        raise FileExistsError('Preserve previous attempt')
    prior = json.loads((ROOT / 'benchmarks/results/trivy-payload-bridge-v1/candidate-freeze.json').read_bytes())
    for name, expected in {**prior['code_sha256'], **prior['input_sha256']}.items():
        assert sha(ROOT / name) == expected
    code = ['benchmarks/trivy_only_payload.py', 'benchmarks/trivy_payload_bridge.py',
            'benchmarks/bounded_jar_evidence.py', 'benchmarks/replay_trivy_only_payload.py']
    atomic_json(output / 'candidate-freeze.json', {
        'mode': 'Disclosed development replay, supplemental Trivy producer with physical witnesses',
        'oracle_read': False, 'runtime_changed': False, 'input_sha256': prior['input_sha256'],
        'code_sha256': {name: sha(ROOT / name) for name in code},
        'experimental_cataloger': CATALOGER, 'policy': 'experimental-trivy-only-payload-v1'})
    for case, (project, pair, previous_name, witness_name, peer_name) in CASES.items():
        directory = output / case
        directory.mkdir()
        work = ROOT / 'benchmarks/.work' / pair
        previous = work / previous_name
        image = json.loads((previous / 'image.syft.json').read_bytes())
        source = json.loads((previous / 'source.syft.json').read_bytes())
        witnesses = json.loads((ROOT / 'benchmarks/results' / witness_name).read_bytes())
        peer = json.loads((ROOT / 'benchmarks/results' / peer_name).read_bytes())
        assert image['descriptor']['version'] == '1.51.1'
        assert [(t['name'], t['version']) for t in peer['metadata']['tools']['components']] == [('trivy', '0.75.0')]
        clean = subprocess.check_output(['git', '-C', str(work / 'src'), 'status', '--porcelain'], text=True).strip()
        assert not clean
        started = time.monotonic()
        adapted, evidence, audit = supplement(image, peer, witnesses, work / 'image.tar')
        atomic_json(directory / 'supplement.json', audit)
        atomic_json(directory / 'image-original.syft.json', image)
        atomic_json(directory / 'peer-image.cdx.json', peer)
        provenance = copy.deepcopy(json.loads((previous / 'provenance.json').read_bytes()))
        provenance['image']['payload_evidence'] = evidence
        provenance['image']['experimental_trivy_only'] = {
            'producer': CATALOGER, 'version': '0.75.0', 'runtime_changed': False,
            'audit_sha256': sha(directory / 'supplement.json'),
            'code_sha256': sha(ROOT / 'benchmarks/trivy_only_payload.py'),
            'original_syft_inventory_preserved': True}
        analysis = work / 'analysis-trivy-only-payload-v1'
        # Explicit benchmark trust registration, paired with mandatory payload gate.
        # Without this registration the service still leaves the new producer UNKNOWN.
        with patch.dict(core._DIRECT_CATALOGERS, {CATALOGER: 'archive_metadata'}), patch.object(
                core, 'PAYLOAD_CATALOGERS', core.PAYLOAD_CATALOGERS | {CATALOGER}), patch.object(
                core, 'RULES_POLICY_VERSION', 'experimental-trivy-only-payload-v1'):
            summary = publish_catalogs(source, adapted, analysis,
                                       Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe')),
                                       rules_assessor, provenance)
        for view in ('final', 'os', 'full'):
            document = json.loads((analysis / (view + '.cdx.json')).read_bytes())
            validate_cyclonedx(document)
            shutil.copyfile(analysis / (view + '.cdx.json'), directory / (view + '.cdx.json'))
        atomic_json(directory / 'run.json', {'project': project, 'runtime_changed': False,
                    'oracle_read': False, 'input_binding_verified': True, 'three_views_schema_valid': True,
                    'explicit_producer': CATALOGER, 'summary': summary,
                    'supplemental_records': len(audit['supplemental']),
                    'supplemental_confirmed': sum(row['status'] == 'CORROBORATED_TRIVY_ONLY' for row in audit['supplemental']),
                    'seconds_including_new_payload_and_conversion': time.monotonic() - started,
                    'peak_rss_bytes': None, 'cache_replay_excludes_acquisition_and_scans': True})
        print(json.dumps({'case': case, 'supplement': audit['supplemental'], 'summary': summary}), flush=True)


if __name__ == '__main__':
    main()

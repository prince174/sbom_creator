"""Predict real final/os/full from physical JAR bytes; no build oracle access."""
import hashlib
import json
import shutil
import subprocess
import time
from unittest.mock import patch

import trivy_only_payload
from replay_trivy_payload_bridge import CASES
from run import ROOT, atomic_json
from seekable_jar_evidence import JarFiles

from sbom_creator import core, payload
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import publish_catalogs, rules_assessor
from sbom_creator.validation import validate_cyclonedx


def main():
    output = ROOT / 'benchmarks/results/seekable-payload-v4'
    if output.exists():
        raise FileExistsError('Preserve previous attempt')
    cases = {key: (pair, previous, peer) for key, (_, pair, previous, _, peer) in CASES.items()}
    cases['dropwizard'] = ('paired-dropwizard-reactor-v1', 'analysis-cached-evidence-input-v3',
                          'dropwizard-frozen-control-v1/prediction-v1/image/sbom.json')
    code = ['benchmarks/seekable_jar_evidence.py', 'benchmarks/seekable_layer_index.py',
            'benchmarks/bounded_jar_evidence.py', 'benchmarks/trivy_only_payload.py',
            'benchmarks/trivy_payload_bridge.py', 'benchmarks/replay_seekable_payload.py']
    atomic_json(output / 'candidate-freeze.json', {'partition': 'disclosed_development',
                'runtime_changed': False, 'oracle_read': False,
                'code_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in code},
                'policy': 'seekable-windows-content-hash-8GiB-verification-128MiB-payload-v3',
                'note': 'ZIP indexes parsed independently per witness and closed; unique-ledger counters differ from cumulative parse-work counters'})
    for case, (pair, previous, peer_path) in cases.items():
        work = ROOT / 'benchmarks/.work' / pair
        prior = work / previous
        directory = output / case
        image = json.loads((prior / 'image.syft.json').read_bytes())
        source = json.loads((prior / 'source.syft.json').read_bytes())
        peer = json.loads((ROOT / 'benchmarks/results' / peer_path).read_bytes())
        if subprocess.check_output(['git', '-C', str(work / 'src'), 'status', '--porcelain'], text=True).strip():
            raise ValueError('Source dirty')
        if image['descriptor']['version'] != '1.51.1':
            raise ValueError('Syft producer differs')
        atomic_json(directory / 'input-hashes.json', {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in [('image_catalog', prior / 'image.syft.json'),
                                       ('source_catalog', prior / 'source.syft.json'),
                                       ('peer', ROOT / 'benchmarks/results' / peer_path)]})
        readers = []

        def make_files(archive, document, readers=readers):
            files = JarFiles(archive, document)
            readers.append(files)
            return files

        started = time.monotonic()
        with patch.object(payload, 'ImageFiles', make_files), patch.object(
                payload, '_java', lambda artifact, files: files.witness(artifact)):
            witnesses = payload.collect(image, work / 'image.tar')
        with patch.object(trivy_only_payload, 'JarFiles', JarFiles):
            adapted, evidence, audit = trivy_only_payload.supplement(image, peer, witnesses, work / 'image.tar')
        atomic_json(directory / 'witnesses.json', witnesses)
        atomic_json(directory / 'audit.json', audit)
        atomic_json(directory / 'image-original.syft.json', image)
        atomic_json(directory / 'peer-image.cdx.json', peer)
        provenance = json.loads((prior / 'provenance.json').read_bytes())
        provenance['image']['payload_evidence'] = evidence
        provenance['image']['experimental_seekable'] = {'policy': 'seekable-payload-v1', 'runtime_changed': False}
        producer = trivy_only_payload.CATALOGER
        analysis = work / 'analysis-seekable-payload-v4'
        with patch.dict(core._DIRECT_CATALOGERS, {producer: 'archive_metadata'}), patch.object(
                core, 'PAYLOAD_CATALOGERS', core.PAYLOAD_CATALOGERS | {producer}), patch.object(
                core, 'RULES_POLICY_VERSION', 'experimental-trivy-only-payload-v1'):
            summary = publish_catalogs(source, adapted, analysis,
                        Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe')), rules_assessor, provenance)
        for view in ('final', 'os', 'full'):
            path = analysis / (view + '.cdx.json')
            validate_cyclonedx(json.loads(path.read_bytes()))
            shutil.copyfile(path, directory / path.name)
        atomic_json(directory / 'run.json', {'oracle_read': False, 'runtime_changed': False,
                    'three_views_valid': True, 'seconds_excluding_cached_scans': time.monotonic()-started,
                    'witness_confirmed': sum(row['status'] == 'confirmed' for row in witnesses.values()),
                    'witness_total': len(witnesses), 'summary': summary,
                    'readers': [{'jar': r.stats, 'layer': r.layers_reader.stats} for r in readers]})
        print(case, sum(row['status'] == 'confirmed' for row in witnesses.values()), len(witnesses), flush=True)


if __name__ == '__main__':
    main()

"""Replay two disclosed development catalogs; no build oracle is opened here."""
import copy
import hashlib
import json
import shutil
import subprocess
import time
from collections import Counter

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from registry_fixture import archive_config
from run import ROOT, atomic_json
from trivy_payload_bridge import bridge

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import publish_catalogs, rules_assessor
from sbom_creator.validation import validate_cyclonedx

CASES = {
    'boot': ('java-spring-petclinic', 'paired-spring-petclinic-v1', 'analysis-bounded-jar-v2',
             'bounded-boot-evidence-v2/witnesses.json', 'trivy-boot-image-v1/sbom.json'),
    'javalin': ('java-javalin', 'paired-javalin-reactor-v1', 'analysis-metadata-archive-v1',
                'bounded-javalin-evidence-v2/witnesses.json', 'trivy-reactor-image-v3/sbom.json'),
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    output = ROOT / 'benchmarks/results/trivy-payload-bridge-v1'
    if output.exists():
        raise FileExistsError('Preserve previous attempt')
    files = [ROOT / 'benchmarks/trivy_payload_bridge.py', ROOT / 'benchmarks/bounded_jar_evidence.py']
    inputs = []
    for _, pair, analysis, witnesses, peer in CASES.values():
        inputs.extend([ROOT / 'benchmarks/.work' / pair / analysis / name for name in
                       ('source.syft.json', 'image.syft.json', 'provenance.json')])
        inputs.extend([ROOT / 'benchmarks/results' / witnesses, ROOT / 'benchmarks/results' / peer])
    atomic_json(output / 'candidate-freeze.json', {
        'mode': 'Disclosed development cached passive catalog replay', 'runtime_changed': False,
        'oracle_read': False, 'code_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in files},
        'input_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in inputs},
        'no_direct_graph_inference': True})
    registry = Registry()
    schemas = ROOT / 'benchmarks/references/trivy-java-source-v1/schemas'
    for path in schemas.glob('*.json'):
        schema = json.loads(path.read_bytes())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    validator = Draft7Validator(json.loads((schemas / 'bom-1.7.schema.json').read_bytes()), registry=registry)
    manifest = json.loads((ROOT / 'benchmarks/java-js-expanded-v1.json').read_bytes())['repositories']
    for key, (project, pair, old_analysis, witness_path, peer_path) in CASES.items():
        directory = output / key
        directory.mkdir()
        work = ROOT / 'benchmarks/.work' / pair
        original = work / old_analysis
        expected = next(p for p in manifest if p['id'] == project)
        def git(*arguments, source_path=work / 'src'):
            return subprocess.check_output(['git', '-C', str(source_path), *arguments], text=True).strip()
        assert git('rev-parse', 'HEAD') == expected['commit'] and not git('status', '--porcelain')
        image = json.loads((original / 'image.syft.json').read_bytes())
        source = json.loads((original / 'source.syft.json').read_bytes())
        witnesses = json.loads((ROOT / 'benchmarks/results' / witness_path).read_bytes())
        peer = json.loads((ROOT / 'benchmarks/results' / peer_path).read_bytes())
        validator.validate(peer)
        config, _ = archive_config(work / 'image.tar')
        assert config == image['source']['metadata']['imageID']
        started = time.monotonic()
        adapted, evidence, audit = bridge(image, peer, witnesses)
        atomic_json(directory / 'bridge.json', audit)
        # Preserve original full inventory separately; the adapted IDs are attributed in audit.
        atomic_json(directory / 'image-original.syft.json', image)
        atomic_json(directory / 'peer-image.cdx.json', peer)
        provenance = copy.deepcopy(json.loads((original / 'provenance.json').read_bytes()))
        provenance['image']['payload_evidence'] = evidence
        provenance['image']['experimental_identity_bridge'] = {
            'mode': 'Unique config+final path+layer+bounded payload witness',
            'code_sha256': sha(ROOT / 'benchmarks/trivy_payload_bridge.py'),
            'audit_sha256': sha(directory / 'bridge.json'), 'runtime_changed': False,
            'input_peer_sha256': sha(ROOT / 'benchmarks/results' / peer_path)}
        analysis = work / 'analysis-trivy-payload-bridge-v1'
        summary = publish_catalogs(source, adapted, analysis,
                                  Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe')),
                                  rules_assessor, provenance)
        for view in ('final', 'os', 'full'):
            validate_cyclonedx(json.loads((analysis / (view + '.cdx.json')).read_bytes()))
            shutil.copyfile(analysis / (view + '.cdx.json'), directory / (view + '.cdx.json'))
        atomic_json(directory / 'run.json', {'project': project, 'commit': expected['commit'],
                    'runtime_changed': False, 'oracle_read': False, 'input_binding_verified': True,
                    'three_views_schema_valid': True, 'bridge_states': dict(Counter(p['status'] for p in audit['packages'])),
                    'elapsed_replay_and_conversion_seconds': time.monotonic() - started, 'summary': summary,
                    'limitations': ['Cached catalog replay, not end-to-end scan timing or runtime integration',
                                    'No direct owner graph, profile activation or execution inference',
                                    'Canonical identities attributed to Trivy, original Syft catalog retained']})
        print(json.dumps({'case': key, 'bridge_states': dict(Counter(p['status'] for p in audit['packages'])),
                          'summary': summary}), flush=True)


if __name__ == '__main__':
    main()

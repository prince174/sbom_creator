"""Two-layer overwrite counterexample for passive Syft content selection."""
import hashlib
import json
import shutil

from run import ROOT, atomic_json, run_command
from syft_go_payload_bridge import read_payload

from sbom_creator.acquire import Settings
from sbom_creator.scanner import scan_image


def main():
    work = ROOT / 'benchmarks/.work/go-payload-overlay-r45'
    work.mkdir(parents=True, exist_ok=True)
    prior = ROOT / 'benchmarks/.work/go-binary-info-r41'
    shutil.copyfile(prior / 'paired-hey-v1.binary', work / 'old.binary')
    shutil.copyfile(prior / 'go-multimain-r39.binary', work / 'new.binary')
    (work / 'Dockerfile').write_text('FROM scratch\nCOPY old.binary /application/app\nCOPY new.binary /application/app\nUSER 65532\nCMD ["/not-executed"]\n', encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!old.binary\n!new.binary\n', encoding='utf-8')
    run_command(['docker', 'build', '--platform', 'linux/amd64', '--iidfile', str(work / 'image.id'), str(work)], work / 'build.log')
    run_command(['docker', 'image', 'save', '-o', str(work / 'image.tar'), (work / 'image.id').read_text().strip()], work / 'save.log')
    settings = Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(work / 'image.tar'))
    original, identity = scan_image('docker.io/sbom-creator-benchmark/overlay:v1', work / 'image.syft.json', settings)
    payload, fresh, output_bytes = read_payload(work / 'image.tar', '/application/app', identity['image_config_digest'])
    correct = hashlib.sha256(payload).hexdigest() == hashlib.sha256((work / 'new.binary').read_bytes()).hexdigest()
    if not correct or payload == (work / 'old.binary').read_bytes():
        raise ValueError('Stale layer content returned')
    unchanged = fresh['artifacts'] == original['artifacts'] and fresh['artifactRelationships'] == original['artifactRelationships']
    if not unchanged:
        raise ValueError('Inventory differs')
    report = {'experiment': 'R45-overlay', 'correct_final_file': correct, 'inventory_graph_unchanged': unchanged,
              'layers': len(fresh['source']['metadata']['layers']), 'private_syft_json_bytes': output_bytes,
              'runtime_changed': False, 'limitation': 'Overwrite tested; deletion/whiteouts, registry backend and many binaries not tested'}
    atomic_json(ROOT / 'docs/syft-go-overlay-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

import hashlib
import json
import tarfile

from go_g1_candidates import declarations
from go_g2_context import context
from go_g2_imports import traverse
from http_integration import command
from paired_express import root_dependencies
from run import ROOT, atomic_json
from verify_paired_hey import json_stream


def main():
    work = ROOT / 'benchmarks/.work/paired-waybackurls-v1'
    out = ROOT / 'benchmarks/references/paired-waybackurls-v1'
    receipt = json.loads((out / 'receipt.json').read_bytes())
    for name, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((out / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Reference changed')
    with tarfile.open(work / 'runtime-app.tar') as archive:
        member = archive.getmember('application/waybackurls')
        if not member.isfile() or member.size > 32 * 1024 * 1024:
            raise ValueError('Unsupported payload')
        payload = archive.extractfile(member).read()
    if hashlib.sha256(payload).hexdigest() != (out / 'binary.sha256').read_text().split()[0]:
        raise ValueError('Binary differs')
    binary = work / 'payload.binary'
    binary.write_bytes(payload)
    info = json.loads(command([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(binary)]))
    module, _ = declarations((work / 'src/go.mod').read_bytes())
    gate = context(info, module, receipt['commit'])
    if gate['status'] != 'ELIGIBLE_CANDIDATE':
        raise ValueError('Unsupported context')
    index = json.loads(command([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'),
                                str(work / 'src'), 'linux', 'amd64']))
    predicted = traverse(module, gate['entry'], index, gate['installed'])
    # Evaluation-only native graph and build SBOM, after prediction.
    packages = json_stream((out / 'packages.json').read_text())
    external = [p for p in packages if p.get('Module') and not p['Module'].get('Main')]
    bom = json.loads((out / 'sbom.json').read_bytes())
    if external or root_dependencies(bom) or predicted['modules']:
        raise ValueError('Expected empty external dependency graph differs')
    atomic_json(ROOT / 'docs/paired-waybackurls-v1.json', {'experiment': 'R56',
        'commit': receipt['commit'], 'partition': 'development', 'native_external_packages': 0,
        'cdx_root_edges': 0, 'candidate_edges': 0, 'precision': None, 'recall': None,
        'receipt_sha256': hashlib.sha256((out / 'receipt.json').read_bytes()).hexdigest(),
        'runtime_changed': False, 'limitation': 'Empty positive graph: no direct accuracy gain'})
    print('R56 verified: paired build, empty native/CDX/candidate graph; accuracy null')


if __name__ == '__main__':
    main()

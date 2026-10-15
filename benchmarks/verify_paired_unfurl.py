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
    work = ROOT / 'benchmarks/.work/paired-unfurl-v1'
    out = ROOT / 'benchmarks/references/paired-unfurl-v1'
    receipt = json.loads((out / 'receipt.json').read_bytes())
    for name, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((out / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Reference changed')
    with tarfile.open(work / 'runtime-app.tar') as archive:
        members = [m for m in archive if m.isfile() and m.name.removeprefix('./').startswith('application/')]
        if len(members) != 1:
            raise ValueError('Ambiguous binary path')
        member = members[0]
        if not member.isfile() or member.size > 32 * 1024 * 1024:
            raise ValueError('Unsupported binary')
        payload = archive.extractfile(member).read()
    if hashlib.sha256(payload).hexdigest() != (out / 'binary.sha256').read_text().split()[0]:
        raise ValueError('Binary differs')
    binary = work / 'payload.binary'
    binary.write_bytes(payload)
    info = json.loads(command([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(binary)]))
    module, declared = declarations((work / 'src/go.mod').read_bytes())
    gate = context(info, module, receipt['commit'])
    if gate['status'] != 'ELIGIBLE_CANDIDATE':
        raise ValueError('Unsupported context: ' + gate.get('reason', ''))
    index = json.loads(command([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'),
                                str(work / 'src'), 'linux', 'amd64']))
    predicted = traverse(module, gate['entry'], index, gate['installed'])
    actual = {tuple(v) for v in predicted['modules']}
    # Evaluation only after prediction; compare native selected-main imports.
    packages = json_stream((out / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in packages}
    expected = set()
    for pkg in packages:
        if pkg.get('Module', {}).get('Main'):
            for imported in pkg.get('Imports', []):
                target = by_path[imported].get('Module', {})
                if target and not target.get('Main'):
                    expected.add((target['Path'], target['Version']))
    bom = json.loads((out / 'sbom.json').read_bytes())
    refs = root_dependencies(bom)
    cdx = {(c['name'], c['version']) for c in bom.get('components', []) if c['bom-ref'] in refs}
    declarations_direct = {(r['name'], r['version']) for r in declared if not r['indirect']}
    if not expected or actual != expected:
        raise ValueError('Native candidate graph differs')
    atomic_json(ROOT / 'docs/paired-unfurl-v1.json', {'experiment': 'R57', 'partition': 'development',
        'commit': receipt['commit'], 'native_selected_main_direct': sorted(expected),
        'cdx_module_root_direct': sorted(cdx), 'candidate_tp': len(actual), 'candidate_fp': 0,
        'declarations_without_cdx_root_edge': sorted(declarations_direct - cdx),
        'candidate_fn': 0, 'candidate_precision': 1.0, 'candidate_recall': 1.0,
        'runtime_changed': False, 'receipt_sha256': hashlib.sha256((out / 'receipt.json').read_bytes()).hexdigest(),
        'limitation': 'Additional positive development fixture, not independent holdout improvement'})
    print('R57 verified: positive native candidate and CDX declaration graphs match')


if __name__ == '__main__':
    main()

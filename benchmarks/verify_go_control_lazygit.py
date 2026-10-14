import json
import subprocess

from go_g2_imports import traverse
from paired_express import application_tree, archive_binding, root_dependencies, sha
from run import ROOT, atomic_json
from verify_paired_hey import json_stream

from sbom_creator.validation import validate_cyclonedx


def main():
    work = ROOT / 'benchmarks/.work/paired-lazygit-v1'
    out = ROOT / 'benchmarks/references/paired-lazygit-v1'
    receipt = json.loads((out / 'receipt.json').read_bytes())
    selection = json.loads((ROOT / 'benchmarks/go-control-g2-positive-v1.json').read_bytes())
    for name, digest in selection['classifier_freeze']['sha256'].items():
        if sha(ROOT / 'benchmarks' / name) != digest:
            raise ValueError('Frozen rules changed')
    for name, digest in receipt['reference_hashes'].items():
        if sha(out / name) != digest:
            raise ValueError('Reference changed')
    for name, digest in receipt['outputs'].items():
        if sha(work / 'analysis' / name) != digest:
            raise ValueError('Analysis changed')
    if sha(work / 'payload.binary') != (out / 'binary.sha256').read_text().split()[0]:
        raise ValueError('Binary changed')
    if application_tree(work / 'build-app.tar') != application_tree(work / 'runtime-app.tar'):
        raise ValueError('Binary tree differs')
    if archive_binding(work / 'image.tar', receipt['image_binding']['index_digest']) != receipt['image_binding']:
        raise ValueError('Image differs')
    info = json.loads(subprocess.check_output([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(work / 'payload.binary')], timeout=30))
    settings = {s['Key']: s['Value'] for s in info['Settings']}
    if settings.get('vcs.revision') != receipt['commit'] or settings.get('vcs.modified') != 'false':
        raise ValueError('Unconfirmed commit')
    index = json.loads(subprocess.check_output([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'), str(work / 'src'), settings['GOOS'], settings['GOARCH']], timeout=30))
    prediction = traverse(info['Main']['Path'], '.', index, {d['Path']: d['Version'] for d in info['Deps']})
    result_path = ROOT / 'docs/go-control-lazygit-v1.json'
    result = json.loads(result_path.read_bytes())
    if json.loads(json.dumps(prediction)) != result['prediction']:
        raise ValueError('Replay differs')
    packages = json_stream((out / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in packages}
    expected = set()
    for pkg in packages:
        if pkg.get('Module', {}).get('Main'):
            for imported in pkg.get('Imports', []):
                module = by_path[imported].get('Module', {})
                if module and not module.get('Main'):
                    expected.add((module['Path'], module['Version']))
    actual = {tuple(v) for v in prediction['modules']}
    if actual != expected:
        raise ValueError('Native selected-main graph differs')
    bom = json.loads((out / 'sbom.json').read_bytes())
    validate_cyclonedx(bom)
    refs = root_dependencies(bom)
    declared = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
    for name in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((work / 'analysis' / (name + '.cdx.json')).read_bytes()))
    result['module_root_edges_without_candidate'] = sorted(declared - actual)
    result['replay_hashes_schemas_verified'] = True
    atomic_json(result_path, result)
    print(json.dumps({'native_matches': len(actual), 'module_scope_difference': sorted(declared - actual), 'verified': True}))


if __name__ == '__main__':
    main()

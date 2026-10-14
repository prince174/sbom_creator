"""Go native package imports, build info, CycloneDX and image binding check."""
import json

from paired_express import application_tree, archive_binding, root_dependencies, sha
from paired_hey import OUT, WORK
from run import ROOT, atomic_json

from sbom_creator.validation import validate_cyclonedx


def json_stream(raw):
    decoder = json.JSONDecoder()
    rows = []
    while raw.strip():
        row, length = decoder.raw_decode(raw.lstrip())
        rows.append(row)
        raw = raw.lstrip()[length:]
    return rows


def main():
    receipt = json.loads((OUT / 'receipt.json').read_bytes())
    for name, digest in receipt['reference_hashes'].items():
        if sha(OUT / name) != digest:
            raise ValueError('Reference changed')
    for name, digest in receipt['outputs'].items():
        if sha(WORK / 'analysis' / name) != digest:
            raise ValueError('Analysis changed')
    if sha(WORK / 'src/go.mod') != receipt['reference_hashes']['go.mod']:
        raise ValueError('Source changed')
    if application_tree(WORK / 'runtime-app.tar') != application_tree(WORK / 'build-app.tar'):
        raise ValueError('Binary tree changed')
    if archive_binding(WORK / 'image.tar', receipt['image_binding']['index_digest']) != receipt['image_binding']:
        raise ValueError('Image binding changed')
    packages = json_stream((OUT / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in packages}
    direct = set()
    for pkg in packages:
        if not pkg.get('Module', {}).get('Main'):
            continue
        for name in pkg.get('Imports', []):
            module = by_path[name].get('Module', {})
            if module and not module.get('Main'):
                direct.add((module['Path'], module['Version']))
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    validate_cyclonedx(bom)
    refs = root_dependencies(bom)
    reference = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
    if reference != direct:
        raise ValueError('Native imported module graph differs from CDX')
    deps = {(line.split()[1], line.split()[2]) for line in (OUT / 'build-info.txt').read_text().splitlines()
            if line.strip().startswith('dep\t')}
    component_modules = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] != bom['metadata']['component']['bom-ref']}
    if deps != component_modules:
        raise ValueError('Binary modules differ from CDX components')
    for name in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((WORK / 'analysis' / (name + '.cdx.json')).read_bytes()))
    report = {'experiment': 'R36', 'native_direct': sorted(direct), 'binary_modules': sorted(deps),
              'receipt_sha256': sha(OUT / 'receipt.json'), 'paired_image_verified': True,
              'three_schemas_valid': True, 'summary': receipt['summary'],
              'direct_precision': None, 'direct_recall': None, 'reason': 'Go direct classifier absent'}
    atomic_json(ROOT / 'docs/paired-hey-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

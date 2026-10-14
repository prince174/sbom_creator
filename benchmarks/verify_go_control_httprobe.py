import json

from paired_express import application_tree, archive_binding, root_dependencies, sha
from run import ROOT

from sbom_creator.validation import validate_cyclonedx


def main():
    work = ROOT / 'benchmarks/.work/paired-httprobe-v1'
    out = ROOT / 'benchmarks/references/paired-httprobe-v1'
    receipt = json.loads((out / 'receipt.json').read_bytes())
    selection = json.loads((ROOT / 'benchmarks/go-control-g2-v1.json').read_bytes())
    for name, digest in selection['classifier_freeze']['sha256'].items():
        if sha(ROOT / 'benchmarks' / name) != digest:
            raise ValueError('Frozen rules changed')
    for name, digest in receipt['reference_hashes'].items():
        if sha(out / name) != digest:
            raise ValueError('Reference changed')
    for name, digest in receipt['outputs'].items():
        if sha(work / 'analysis' / name) != digest:
            raise ValueError('Analysis changed')
    if application_tree(work / 'build-app.tar') != application_tree(work / 'runtime-app.tar'):
        raise ValueError('Tree differs')
    if archive_binding(work / 'image.tar', receipt['image_binding']['index_digest']) != receipt['image_binding']:
        raise ValueError('Image binding differs')
    bom = json.loads((out / 'sbom.json').read_bytes())
    validate_cyclonedx(bom)
    if root_dependencies(bom):
        raise ValueError('Not the empty control')
    for name in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((work / 'analysis' / (name + '.cdx.json')).read_bytes()))
    result = json.loads((ROOT / 'docs/go-control-httprobe-v1.json').read_bytes())
    if result['candidate_fp'] or result['prediction']['modules'] or result['precision'] is not None:
        raise ValueError('Invalid empty-control result')
    print('Frozen rules, reference hashes, image binding, empty control and four schemas verified')


if __name__ == '__main__':
    main()

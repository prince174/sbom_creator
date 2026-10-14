import json

from go_g1_candidates import predict
from go_multimain_clean import OUT, WORK
from paired_express import application_tree, archive_binding, sha
from run import ROOT

from sbom_creator.validation import validate_cyclonedx


def main():
    receipt = json.loads((OUT / 'receipt.json').read_bytes())
    for name, digest in receipt['reference_hashes'].items():
        if sha(OUT / name) != digest:
            raise ValueError('Reference changed')
    for name, digest in receipt['outputs'].items():
        if sha(WORK / 'analysis' / name) != digest:
            raise ValueError('Analysis changed')
    info = (OUT / 'build-info.txt').read_text()
    if 'vcs.modified=false' not in info or ('vcs.revision=' + receipt['commit']) not in info:
        raise ValueError('Commit/clean build not confirmed')
    if (OUT / 'git-status-after.txt').read_text().strip():
        raise ValueError('Dirty builder checkout')
    tree = application_tree(WORK / 'runtime-app.tar')
    if tree != application_tree(WORK / 'build-app.tar') or tree != json.loads((OUT / 'application-tree.json').read_bytes()):
        raise ValueError('Tree mismatch')
    if archive_binding(WORK / 'image.tar', receipt['image_binding']['index_digest']) != receipt['image_binding']:
        raise ValueError('Image mismatch')
    report = json.loads((ROOT / 'docs/go-multimain-v2.json').read_bytes())
    prediction = predict((OUT / 'go.mod').read_bytes(), json.loads((WORK / 'analysis/image.syft.json').read_bytes()), receipt['commit'])
    if prediction != report['prediction']:
        raise ValueError('Prediction changed')
    for name in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((WORK / 'analysis' / (name + '.cdx.json')).read_bytes()))
    validate_cyclonedx(json.loads((OUT / 'sbom.json').read_bytes()))
    print('Clean exact-commit binary, hashes, trees, OCI, prediction and four schemas verified')


if __name__ == '__main__':
    main()

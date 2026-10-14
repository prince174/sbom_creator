"""Complete a prebuilt external Go pair; no oracle supplied to analyzer."""
import base64
import hashlib
import json
import shutil
import subprocess

import paired_express as shared
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

WORK = ROOT / 'benchmarks/.work/paired-hey-v1'
OUT = ROOT / 'benchmarks/references/paired-hey-v1'
COMMIT = 'af177063f85bd935c55f1f2ee59c2898d9654f82'


def main(*, project_id='go-hey', experiment='R36'):
    if (OUT / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    source = WORK / 'src'
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() != COMMIT:
        raise ValueError('Wrong commit')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=source, text=True).strip():
        raise ValueError('Dirty source')
    if shared.sha(WORK / 'Dockerfile') != shared.sha(ROOT / 'benchmarks/paired-hey.Dockerfile'):
        raise ValueError('Recipe changed')
    OUT.mkdir(parents=True, exist_ok=True)
    shared.WORK = WORK
    for stage in ('build', 'runtime'):
        identity = (WORK / (stage + '.id')).read_text().strip()
        exports = [('/application', WORK / (stage + '-app.tar'), True)]
        if stage == 'build':
            exports.append(('/reference/.', OUT, False))
        shared.export_from_image(identity, exports, stage)
    tree = shared.application_tree(WORK / 'runtime-app.tar')
    if tree != shared.application_tree(WORK / 'build-app.tar'):
        raise ValueError('Binary tree differs')
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    validate_cyclonedx(bom)
    refs = shared.root_dependencies(bom)
    direct = [c['purl'] for c in bom['components'] if c['bom-ref'] in refs]
    runtime = (WORK / 'runtime.id').read_text().strip()
    archive = WORK / 'image.tar'
    if not archive.exists():
        run_command(['docker', 'image', 'save', '-o', str(archive), runtime], WORK / 'save.log', timeout=300)
    analysis = WORK / 'analysis'
    summary = analyze_local(source, 'docker.io/sbom-creator-benchmark/paired-hey:v1', analysis,
                            Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(archive)))
    binding = shared.archive_binding(archive, runtime)
    image = json.loads((analysis / 'image.syft.json').read_bytes())
    config = base64.b64decode(image['source']['metadata']['config'], validate=True)
    if 'sha256:' + hashlib.sha256(config).hexdigest() != binding['config_digest']:
        raise ValueError('Image mismatch')
    for name in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis / (name + '.cdx.json')).read_bytes()))
    for path, name in [(WORK / 'Dockerfile', 'Dockerfile'), (source / 'go.mod', 'go.mod'),
                       (WORK / 'generator-provenance.json', 'generator-provenance.json')]:
        shutil.copyfile(path, OUT / name)
    atomic_json(OUT / 'application-tree.json', tree)
    atomic_json(OUT / 'receipt.json', {'experiment': experiment, 'project': project_id, 'commit': COMMIT,
                'image_binding': binding, 'artifact_tree_equal': True, 'reference_only_for_evaluation': True,
                'reference_hashes': {p.name: shared.sha(p) for p in OUT.iterdir() if p.is_file()},
                'outputs': {p.name: shared.sha(p) for p in analysis.iterdir() if p.is_file()},
                'summary': summary, 'direct_precision': None, 'direct_recall': None})
    print(json.dumps({'reference_direct': direct, 'summary': summary}))


if __name__ == '__main__':
    main()

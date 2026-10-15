"""Complete the existing Rust fd checkpoint without rebuilding it."""
import base64
import hashlib
import json
import shutil
from collections import Counter

import paired_express as shared
from build_references import inspect_bom
from http_integration import command
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx


def main():
    work = ROOT / 'benchmarks/.work/paired-fd-v1'
    out = ROOT / 'benchmarks/references/paired-fd-v1'
    if (out / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    source = work / 'src'
    project = next(p for p in json.loads((ROOT / 'benchmarks/manifest.json').read_bytes())['repositories'] if p['id'] == 'rust-fd')
    if command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != project['commit'] or command(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('Source commit/cleanliness differs')
    shared.WORK = work
    for stage, path in [('build', '/out'), ('runtime', '/app')]:
        shared.export_from_image((work / (stage + '.id')).read_text().strip(),
                                 [(path, work / (stage + '-app.tar'), True)], stage)
    tree = shared.application_tree(work / 'build-app.tar')
    if not tree or tree != shared.application_tree(work / 'runtime-app.tar'):
        raise ValueError('Builder/runtime application trees differ')
    runtime = (work / 'runtime.id').read_text().strip()
    archive = work / 'image.tar'
    if not archive.exists():
        run_command(['docker', 'image', 'save', '-o', str(archive), runtime], work / 'save.log', timeout=300)
    binding = shared.archive_binding(archive, runtime)
    analysis = work / 'analysis'
    if (analysis / 'summary.json').exists():
        summary = json.loads((analysis / 'summary.json').read_bytes())
    else:
        summary = analyze_local(source, 'docker.io/sbom-creator-benchmark/paired-fd:v1', analysis,
            Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(archive)))
    image = json.loads((analysis / 'image.syft.json').read_bytes())
    config = base64.b64decode(image['source']['metadata']['config'], validate=True)
    if 'sha256:' + hashlib.sha256(config).hexdigest() != binding['config_digest']:
        raise ValueError('Analyzer image binding differs')
    for name in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis / (name + '.cdx.json')).read_bytes()))
    # Reference graph is inspected only after the analyzer has finished.
    reference = work / 'reference'
    bom = json.loads((reference / 'sbom.json').read_bytes())
    inspect_bom(reference / 'sbom.json')
    metadata = json.loads((reference / 'filtered.json').read_bytes())
    root = bom['metadata']['component']['bom-ref']
    node = next(n for n in metadata['resolve']['nodes'] if n['id'] == root)
    deps = {d['pkg']: d for d in node['deps']}
    edges = shared.root_dependencies(bom)
    if any(edge not in deps for edge in edges):
        raise ValueError('CDX edge absent from filtered graph')
    labels = [{'owner': root, 'ref': edge, 'dep_kinds': deps[edge]['dep_kinds'],
               'execution_proven': False} for edge in edges]
    out.mkdir(parents=True, exist_ok=True)
    for path in reference.iterdir():
        if path.is_file():
            shutil.copyfile(path, out / path.name)
    shutil.copyfile(work / 'Dockerfile', out / 'Dockerfile')
    shutil.copyfile(source / 'Cargo.toml', out / 'Cargo.toml')
    shutil.copyfile(source / 'Cargo.lock', out / 'Cargo.lock')
    atomic_json(out / 'application-tree.json', tree)
    atomic_json(out / 'direct-edge-kinds.json', labels)
    atomic_json(out / 'receipt.json', {'experiment': 'R60', 'project': 'rust-fd', 'commit': project['commit'],
        'image_binding': binding, 'artifact_tree_equal': True, 'reference_only_for_evaluation': True,
        'reference_hashes': {p.name: shared.sha(p) for p in out.iterdir() if p.is_file() and p.name != 'receipt.json'},
        'outputs': {p.name: shared.sha(p) for p in analysis.iterdir() if p.is_file()},
        'summary': summary, 'direct_precision': None, 'direct_recall': None})
    atomic_json(ROOT / 'docs/paired-fd-v1.json', {'experiment': 'R60', 'project': 'rust-fd',
        'root_edges': len(edges), 'kind_occurrences': dict(Counter(k['kind'] or 'normal' for row in labels for k in row['dep_kinds'])),
        'summary': summary, 'receipt_sha256': shared.sha(out / 'receipt.json'), 'runtime_changed': False,
        'direct_accuracy': None, 'limitation': 'Paired reference; scopes recorded, execution not proven; no classifier gain claimed'})
    print('R60 passed: paired tree, image binding, schemas and scoped reference labels')


if __name__ == '__main__':
    main()

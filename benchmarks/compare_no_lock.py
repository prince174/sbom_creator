"""No-project-lock ablation of real JS pairs; derivative image, not a new oracle."""
import argparse
import json
import re
import shutil
import subprocess
import time
from pathlib import PurePosixPath

from compare_java_js import all_components, coord
from paired_express import application_tree, export_from_image
from run import ROOT, atomic_json, run_command
from score_project_components import metrics

from sbom_creator.acquire import Settings
from sbom_creator.evaluation import compare
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

LOCKS = {'package-lock.json', '.package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock',
         'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'}


def verify_variant(original, work, image, analysis):
    exported = work / 'runtime-app.tar'
    if not exported.exists():
        export_from_image(image, [('/app', exported, True)], 'no-lock')
    previous = application_tree(original / 'runtime-app.tar')
    current = application_tree(exported)
    expected = [r for r in previous if PurePosixPath(r['path']).name not in LOCKS]
    if current != expected:
        raise ValueError('Derivative changes more than project lockfiles')
    final = json.loads((analysis / 'final.cdx.json').read_bytes())
    projected = {coord(c) for c in all_components(final) if coord(c) and any(
        p.get('name', '').startswith('syft:location:') and p.get('name', '').endswith(':path')
        and p.get('value', '').startswith('/app/') for p in c.get('properties', []))}
    return {'unchanged_nonlock_application_tree': True,
            'removed_lock_paths': [r['path'] for r in previous if PurePosixPath(r['path']).name in LOCKS],
            'final_project_coordinates': sorted(projected)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pair', required=True)
    parser.add_argument('--corpus', choices=('original', 'expanded'), default='original')
    args = parser.parse_args()
    if not re.fullmatch(r'paired-[a-z0-9-]+-v[0-9]+', args.pair):
        raise ValueError('Invalid fixture pair')
    if args.corpus == 'expanded':
        selected = {p['id'] for p in json.loads((ROOT / 'benchmarks/java-js-expanded-v1.json').read_bytes())['repositories']}
    else:
        selected = set(json.loads((ROOT / 'benchmarks/java-js-twenty-split.json').read_bytes())['development_projects'])
    original = ROOT / 'benchmarks/.work' / args.pair
    reference_dir = ROOT / 'benchmarks/references' / args.pair
    receipt = json.loads((reference_dir / 'receipt.json').read_bytes())
    if receipt['project'] not in selected or not receipt['project'].startswith('javascript-'):
        raise ValueError('Select a fixed JS development pair')
    if subprocess.check_output(['git', '-C', str(original / 'src'), 'rev-parse', 'HEAD'], text=True).strip() != receipt['commit']:
        raise ValueError('Original source revision differs')
    namespace = 'no-lock-expanded-v1' if args.corpus == 'expanded' else 'no-lock-v1'
    work = ROOT / 'benchmarks/.work' / namespace / args.pair
    out = ROOT / 'benchmarks/results' / namespace / args.pair
    if (out / 'report.json').exists():
        raise FileExistsError('Immutable completed ablation')
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    source = work / 'src'
    if not source.exists():
        shutil.copytree(original / 'src', source, ignore=shutil.ignore_patterns('.git', *LOCKS))
    if any(p.name in LOCKS for p in source.rglob('*')):
        raise ValueError('Source lockfile remains')
    parent = (original / 'runtime.id').read_text().strip()
    tag = 'sbom-creator-benchmark/no-lock-parent:' + parent.removeprefix('sha256:')
    subprocess.run(['docker', 'image', 'tag', parent, tag], check=True, capture_output=True)
    names = ' -o '.join('-name ' + name for name in sorted(LOCKS))
    dockerfile = f'FROM {tag}\nUSER root\nRUN find /app -type f \\( {names} \\) -print -delete\nUSER node\n'
    (work / 'Dockerfile').write_text(dockerfile, encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n', encoding='utf-8')
    resumed_analysis = (work / 'analysis/summary.json').exists()
    start = time.monotonic()
    if not (work / 'image.id').exists():
        run_command(['docker', 'build', '--iidfile', str(work / 'image.id'), str(work)], work / 'build.log', timeout=180)
    image = (work / 'image.id').read_text().strip()
    archive = work / 'image.tar'
    if not archive.exists():
        run_command(['docker', 'image', 'save', '-o', str(archive), image], work / 'save.log', timeout=180)
    analysis = work / 'analysis'
    if not (analysis / 'summary.json').exists():
        analyze_local(source, 'docker.io/sbom-creator-benchmark/no-lock:v1', analysis,
                      Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(archive)))
    for view in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis / (view + '.cdx.json')).read_bytes()))
    catalog = json.loads((analysis / 'image.syft.json').read_bytes())
    predicted = {coord(a) for a in catalog['artifacts'] if coord(a) and
                 any(p.get('path', '').startswith('/app/') for p in a.get('locations', []))}
    proof = verify_variant(original, work, image, analysis)
    inventory = predicted
    predicted = set(proof['final_project_coordinates'])
    proof['image_inventory_equals_final_projection'] = inventory == predicted
    atomic_json(out / 'variant-proof.json', proof)
    # Oracle first opened only after unchanged service analysis.
    reference = json.loads((reference_dir / 'sbom.json').read_bytes())
    owner = coord(reference['metadata']['component'])
    predicted.discard(owner)
    inventory = inventory - {owner}
    expected = {coord(c) for c in all_components(reference) if coord(c)} - {owner}
    report = {'project': receipt['project'], 'original_commit': receipt['commit'],
              'source_variant': 'Only project lockfiles and .git omitted; no dependency resolution',
              'image_variant': 'Original runtime plus deletion of project lockfiles under /app only',
              'parent_image': parent, 'derivative_image': image, 'project_scope': '/app/',
              'components': metrics(predicted, expected), 'direct': compare(analysis, reference, 'runtime'),
              'image_inventory_components': metrics(inventory, expected),
              'inventory_only_coordinates': sorted(inventory - predicted),
              'seconds': None if resumed_analysis else time.monotonic() - start,
              'validation_resume_seconds': time.monotonic() - start if resumed_analysis else None,
              'timing_note': 'Validation-only resume; full failed-attempt timing not recovered' if resumed_analysis else 'Full derivative build/export/analysis/validation wall time',
              'missing': sorted(expected - predicted),
              'extra': sorted(predicted - expected), 'runtime_changed': False,
              'limitation': 'Fixed fixture installation path; derived inputs, original oracle. Platform inventory preserved.'}
    atomic_json(out / 'report.json', report)
    shutil.copyfile(work / 'Dockerfile', out / 'Dockerfile')
    print(json.dumps(report))


if __name__ == '__main__':
    main()

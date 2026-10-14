"""Repeat synthetic Go pair after Linux checkout normalization, new namespace."""
import json
import shutil
import subprocess

import paired_hey
from go_g1_candidates import predict
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json, run_command
from verify_paired_hey import json_stream

WORK = ROOT / 'benchmarks/.work/go-multimain-r39'
OUT = ROOT / 'benchmarks/references/go-multimain-v2'


def main():
    if (OUT / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    prior = ROOT / 'benchmarks/.work/go-multimain-r38'
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / 'src'
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(prior / 'src'), str(source)], WORK / 'clone.log')
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=prior / 'src', text=True).strip()
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', commit], WORK / 'checkout.log', cwd=source)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    for name in ('cyclonedx-gomod', 'generator-provenance.json'):
        shutil.copyfile(prior / name, WORK / name)
    recipe = (ROOT / 'benchmarks/paired-hey.Dockerfile').read_text()
    recipe = recipe.replace('RUN --mount=type=cache',
                            'RUN git status --porcelain > /tmp/status-before.txt && git -c core.autocrlf=false reset --hard HEAD && '
                            'git status --porcelain > /tmp/status-after.txt && test ! -s /tmp/status-after.txt\nRUN --mount=type=cache', 1)
    recipe = recipe.replace('go build -buildvcs=true',
                            'cp /tmp/status-before.txt /reference/git-status-before.txt && cp /tmp/status-after.txt /reference/git-status-after.txt && go build -buildvcs=true')
    (WORK / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (WORK / '.dockerignore').write_text('**\n!Dockerfile\n!cyclonedx-gomod\n!src/\n!src/**\n', encoding='utf-8')
    for stage in ('build', 'runtime'):
        run_command(['docker', 'build', '--platform', 'linux/amd64', '--target', stage, '--iidfile', str(WORK / (stage + '.id')), str(WORK)], WORK / (stage + '.log'), timeout=1200)
    paired_hey.WORK, paired_hey.OUT, paired_hey.COMMIT = WORK, OUT, commit
    paired_hey.main(project_id='synthetic-hey-multimain-clean', experiment='R39', recipe_path=WORK / 'Dockerfile')
    prediction = predict((source / 'go.mod').read_bytes(), json.loads((WORK / 'analysis/image.syft.json').read_bytes()), commit)
    packages = json_stream((OUT / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in packages}
    native = set()
    for pkg in packages:
        if pkg.get('Module', {}).get('Main'):
            for imported in pkg.get('Imports', []):
                module = by_path[imported].get('Module', {})
                if module and not module.get('Main'):
                    native.add((module['Path'], module['Version']))
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    refs = root_dependencies(bom)
    declared = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
    actual = {(c['name'], c['version']) for c in prediction['candidates']}
    clean = 'vcs.modified=false' in (OUT / 'build-info.txt').read_text()
    report = {'experiment': 'R39', 'synthetic': True, 'fixture_commit': commit, 'binary_clean': clean,
              'prediction': prediction, 'module_root_direct': sorted(declared), 'selected_main_import_direct': sorted(native),
              'extra_candidates_for_selected_main': sorted(actual - native),
              'module_root_candidate_matches': len(actual & declared), 'runtime_changed': False,
              'direct_precision': None, 'direct_recall': None, 'receipt_sha256': sha(OUT / 'receipt.json'),
              'limitation': 'Two distinct labels; synthetic scope counterexample, not overall accuracy'}
    if not clean:
        raise ValueError('Still dirty; exclude from evaluation')
    atomic_json(ROOT / 'docs/go-multimain-v2.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

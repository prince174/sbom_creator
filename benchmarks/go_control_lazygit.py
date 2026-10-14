"""Positive fixed Go control; frozen rules may abstain, never tuned here."""
import json
import shutil
import subprocess
import tarfile

import paired_hey
from go_g1_candidates import declarations
from go_g2_imports import traverse
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json, run_command
from verify_paired_hey import json_stream

WORK = ROOT / 'benchmarks/.work/paired-lazygit-v1'
OUT = ROOT / 'benchmarks/references/paired-lazygit-v1'


def main():
    selection = json.loads((ROOT / 'benchmarks/go-control-g2-positive-v1.json').read_bytes())
    for name, digest in selection['classifier_freeze']['sha256'].items():
        if sha(ROOT / 'benchmarks' / name) != digest:
            raise ValueError('Frozen rules changed')
    if (OUT / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / 'src'
    commit = selection['project']['commit']
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(ROOT / 'benchmarks/.work/go-lazygit/src'), str(source)], WORK / 'clone.log')
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', commit], WORK / 'checkout.log', cwd=source)
    for name in ('cyclonedx-gomod', 'generator-provenance.json'):
        shutil.copyfile(paired_hey.WORK / name, WORK / name)
    recipe = (ROOT / 'benchmarks/paired-hey.Dockerfile').read_text().replace('/application/hey', '/application/lazygit')
    recipe = recipe.replace('go list -m -json all', 'go list -m -json')
    recipe = recipe.replace('RUN --mount=type=cache', 'RUN git -c core.autocrlf=false reset --hard HEAD && test -z "$(git status --porcelain)"\nRUN --mount=type=cache', 1)
    (WORK / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (WORK / '.dockerignore').write_text('**\n!Dockerfile\n!cyclonedx-gomod\n!src/\n!src/**\n', encoding='utf-8')
    for stage in ('build', 'runtime'):
        run_command(['docker', 'build', '--platform', 'linux/amd64', '--target', stage, '--iidfile', str(WORK / (stage + '.id')), str(WORK)], WORK / (stage + '.log'), timeout=1800)
    paired_hey.WORK, paired_hey.OUT, paired_hey.COMMIT = WORK, OUT, commit
    paired_hey.main(project_id='go-lazygit', experiment='R44', recipe_path=WORK / 'Dockerfile')
    with tarfile.open(WORK / 'runtime-app.tar') as archive:
        members = [m for m in archive if m.name.removeprefix('./') == 'application/lazygit']
        if len(members) != 1 or not members[0].isfile() or members[0].size > 64 * 1024 * 1024:
            raise ValueError('Unsupported payload')
        payload = archive.extractfile(members[0]).read()
    binary = WORK / 'payload.binary'
    binary.write_bytes(payload)
    try:
        info = json.loads(subprocess.check_output([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(binary)], timeout=30))
        settings = {s['Key']: s['Value'] for s in info['Settings']}
        if settings.get('vcs.revision') != commit or settings.get('vcs.modified') != 'false':
            raise ValueError('Unconfirmed commit')
        if settings.get('CGO_ENABLED') != '0' or settings.get('-tags') or settings.get('GOAMD64') != 'v1' or any(settings.get(k) for k in ('-race', '-msan', '-asan', 'GOEXPERIMENT')):
            raise ValueError('Unsupported context')
        module, _ = declarations((source / 'go.mod').read_bytes())
        if (source / 'go.work').exists() or module != info['Main']['Path'] or info['Path'] != module:
            raise ValueError('Unsupported workspace/entry')
        deps = info.get('Deps') or []
        if any(d.get('Replace') for d in deps):
            raise ValueError('Unsupported replacement')
        index = json.loads(subprocess.check_output([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'), str(source), settings['GOOS'], settings['GOARCH']], timeout=30, stderr=subprocess.PIPE))
        if index['parser_version'] != info['GoVersion']:
            raise ValueError('Parser mismatch')
        prediction = traverse(module, '.', index, {d['Path']: d['Version'] for d in deps})
    except (ValueError, subprocess.CalledProcessError) as error:
        prediction = {'status': 'UNKNOWN', 'reason': str(error), 'modules': []}
    # Read oracle after prediction; no rule mutation allowed on the control.
    packages = json_stream((OUT / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in packages}
    expected = set()
    for pkg in packages:
        if pkg.get('Module', {}).get('Main'):
            for imported in pkg.get('Imports', []):
                target = by_path[imported].get('Module', {})
                if target and not target.get('Main'):
                    expected.add((target['Path'], target['Version']))
    actual = {tuple(v) for v in prediction['modules']}
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    refs = root_dependencies(bom)
    declared = {(c['name'], c['version']) for c in bom.get('components', []) if c['bom-ref'] in refs}
    report = {'experiment': 'R44', 'partition': selection['partition'], 'prediction': prediction,
              'native_selected_main_edges': len(expected), 'cdx_module_root_edges': len(declared),
              'candidate_tp': len(actual & expected), 'candidate_fp': len(actual - expected),
              'reference_edges_without_candidate': len(expected - actual),
              'candidate_recall': len(actual & expected) / len(expected) if expected else None,
              'candidate_precision': len(actual & expected) / len(actual) if actual else None,
              'runtime_changed': False, 'frozen_rules_changed': False,
              'receipt_sha256': sha(OUT / 'receipt.json')}
    atomic_json(ROOT / 'docs/go-control-lazygit-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

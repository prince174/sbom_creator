"""Fixed Go holdout pair, no changes to frozen G2 rules."""
import hashlib
import json
import shutil
import subprocess
import tarfile

import paired_hey
from go_g1_candidates import declarations
from go_g2_imports import traverse
from paired_express import sha
from run import ROOT, atomic_json, run_command
from verify_paired_hey import json_stream

WORK = ROOT / 'benchmarks/.work/paired-httprobe-v1'
OUT = ROOT / 'benchmarks/references/paired-httprobe-v1'


def main():
    selection = json.loads((ROOT / 'benchmarks/go-control-g2-v1.json').read_bytes())
    for name, digest in selection['classifier_freeze']['sha256'].items():
        if sha(ROOT / 'benchmarks' / name) != digest:
            raise ValueError('Frozen rule changed')
    commit = selection['project']['commit']
    if (OUT / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / 'src'
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(ROOT / 'benchmarks/.work/go-httprobe/src'), str(source)], WORK / 'clone.log')
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', commit], WORK / 'checkout.log', cwd=source)
    for name in ('cyclonedx-gomod', 'generator-provenance.json'):
        shutil.copyfile(paired_hey.WORK / name, WORK / name)
    recipe = (ROOT / 'benchmarks/paired-hey.Dockerfile').read_text().replace('/application/hey', '/application/httprobe')
    recipe = recipe.replace('RUN --mount=type=cache', 'RUN git -c core.autocrlf=false reset --hard HEAD && test -z "$(git status --porcelain)"\nRUN --mount=type=cache', 1)
    (WORK / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (WORK / '.dockerignore').write_text('**\n!Dockerfile\n!cyclonedx-gomod\n!src/\n!src/**\n', encoding='utf-8')
    for stage in ('build', 'runtime'):
        run_command(['docker', 'build', '--platform', 'linux/amd64', '--target', stage, '--iidfile', str(WORK / (stage + '.id')), str(WORK)], WORK / (stage + '.log'), timeout=1200)
    paired_hey.WORK, paired_hey.OUT, paired_hey.COMMIT = WORK, OUT, commit
    paired_hey.main(project_id='go-httprobe', experiment='R43', recipe_path=WORK / 'Dockerfile')
    # Read the binary exported from runtime image, never reference build-info.
    with tarfile.open(WORK / 'runtime-app.tar') as files:
        members = [m for m in files if m.name.removeprefix('./') == 'application/httprobe']
        if len(members) != 1 or not members[0].isfile() or members[0].size > 64 * 1024 * 1024:
            raise ValueError('Unsupported runtime payload')
        payload = files.extractfile(members[0]).read()
    binary = WORK / 'payload.binary'
    binary.write_bytes(payload)
    info = json.loads(subprocess.check_output([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(binary)], timeout=30))
    settings = {s['Key']: s['Value'] for s in info['Settings']}
    if settings.get('vcs.revision') != commit or settings.get('vcs.modified') != 'false' or settings.get('CGO_ENABLED') != '0' or settings.get('-tags'):
        raise ValueError('Unsupported binary context')
    module, _ = declarations((source / 'go.mod').read_bytes())
    if info['Path'] != module or info['Main']['Path'] != module:
        raise ValueError('Unexpected entry')
    index = json.loads(subprocess.check_output([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'), str(source), settings['GOOS'], settings['GOARCH']], timeout=30))
    if index['parser_version'] != info['GoVersion']:
        raise ValueError('Context mismatch')
    installed = {d['Path']: d['Version'] for d in info.get('Deps') or []}
    prediction = traverse(module, '.', index, installed)
    # Oracle access only after prediction. Empty cases never gain precision100%.
    native = json_stream((OUT / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in native}
    expected = set()
    for pkg in native:
        if pkg.get('Module', {}).get('Main'):
            for imported in pkg.get('Imports', []):
                m = by_path[imported].get('Module', {})
                if m and not m.get('Main'):
                    expected.add((m['Path'], m['Version']))
    actual = {tuple(m) for m in prediction['modules']}
    report = {'experiment': 'R43', 'partition': selection['partition'], 'project': 'go-httprobe',
              'prediction': prediction, 'reference_main_direct': sorted(expected),
              'candidate_tp': len(actual & expected), 'candidate_fp': len(actual - expected),
              'candidate_fn': len(expected - actual), 'precision': None, 'recall': None,
              'binary_sha256': hashlib.sha256(payload).hexdigest(), 'runtime_changed': False,
              'reason': 'Empty external-dependency control; only absence of invented edges tested',
              'receipt_sha256': sha(OUT / 'receipt.json')}
    atomic_json(ROOT / 'docs/go-control-httprobe-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

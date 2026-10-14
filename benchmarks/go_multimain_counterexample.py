"""External synthetic derivative: non-indirect x/text used by another main."""
import argparse
import json
import shutil
import subprocess

import paired_hey
from go_g1_candidates import predict
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json, run_command

WORK = ROOT / 'benchmarks/.work/go-multimain-r38'
OUT = ROOT / 'benchmarks/references/go-multimain-v1'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--resume-built-images', action='store_true')
    args = parser.parse_args()
    if (OUT / 'receipt.json').exists():
        raise FileExistsError('Immutable reference exists')
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / 'src'
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', str(paired_hey.WORK / 'src'), str(source)], WORK / 'clone.log')
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', paired_hey.COMMIT], WORK / 'checkout.log', cwd=source)
        raw = (source / 'go.mod').read_text()
        if 'golang.org/x/text v0.3.0 // indirect' not in raw:
            raise ValueError('Unexpected base manifest')
        (source / 'go.mod').write_text(raw.replace('golang.org/x/text v0.3.0 // indirect', 'golang.org/x/text v0.3.0'), encoding='utf-8')
        other = source / 'cmd/other'
        other.mkdir(parents=True)
        (other / 'main.go').write_text('package main\nimport "golang.org/x/text/unicode/norm"\nfunc main() { println(norm.NFC.String("test")) }\n', encoding='utf-8')
        run_command(['git', 'add', 'go.mod', 'cmd/other/main.go'], WORK / 'add.log', cwd=source)
        run_command(['git', '-c', 'user.name=SBOM benchmark', '-c', 'user.email=benchmark@example.invalid',
                     'commit', '-m', 'Synthetic additional main imports x/text'], WORK / 'commit.log', cwd=source)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    shutil.copyfile(paired_hey.WORK / 'cyclonedx-gomod', WORK / 'cyclonedx-gomod')
    shutil.copyfile(paired_hey.WORK / 'generator-provenance.json', WORK / 'generator-provenance.json')
    shutil.copyfile(ROOT / 'benchmarks/paired-hey.Dockerfile', WORK / 'Dockerfile')
    (WORK / '.dockerignore').write_text('**\n!Dockerfile\n!cyclonedx-gomod\n!src/\n!src/**\n', encoding='utf-8')
    if not args.resume_built_images:
        for stage in ('build', 'runtime'):
            run_command(['docker', 'build', '--platform', 'linux/amd64', '--target', stage,
                         '--iidfile', str(WORK / (stage + '.id')), str(WORK)], WORK / (stage + '.log'), timeout=1200)
    paired_hey.WORK, paired_hey.OUT, paired_hey.COMMIT = WORK, OUT, commit
    paired_hey.main(project_id='synthetic-hey-multimain', experiment='R38')
    # Analyzer candidates computed before the reference graph is used for scoring.
    image = json.loads((WORK / 'analysis/image.syft.json').read_bytes())
    prediction = predict((source / 'go.mod').read_bytes(), image, commit)
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    refs = root_dependencies(bom)
    expected = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
    actual = {(c['name'], c['version']) for c in prediction['candidates']}
    report = {'experiment': 'R38', 'synthetic': True, 'base_commit': 'af177063f85bd935c55f1f2ee59c2898d9654f82',
              'fixture_commit': commit, 'prediction': prediction, 'reference_direct': sorted(expected),
              'candidate_extra': sorted(actual - expected), 'candidate_matches': len(actual & expected),
              'runtime_changed': False, 'direct_precision': None, 'direct_recall': None,
              'receipt_sha256': sha(OUT / 'receipt.json'),
              'reason': 'One targeted multimain counterexample; not representative accuracy'}
    atomic_json(ROOT / 'docs/go-multimain-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

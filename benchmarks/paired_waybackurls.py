"""Controlled development build/reference pair; external harness only."""
import json
import shutil

import paired_hey
from run import ROOT, run_command


def main():
    project = next(r for r in json.loads((ROOT / 'benchmarks/manifest.json').read_bytes())['repositories']
                   if r['id'] == 'go-waybackurls')
    work = ROOT / 'benchmarks/.work/paired-waybackurls-v1'
    out = ROOT / 'benchmarks/references/paired-waybackurls-v1'
    if (out / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    work.mkdir(parents=True, exist_ok=True)
    source = work / 'src'
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', '--no-checkout',
                     str(ROOT / 'benchmarks/.work/go-waybackurls/src'), str(source)], work / 'clone.log')
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', project['commit']],
                    work / 'checkout.log', cwd=source)
    for name in ('cyclonedx-gomod', 'generator-provenance.json'):
        shutil.copyfile(paired_hey.WORK / name, work / name)
    recipe = (ROOT / 'benchmarks/paired-hey.Dockerfile').read_text().replace('/application/hey', '/application/waybackurls')
    recipe = recipe.replace('RUN --mount=type=cache',
        'RUN git -c core.autocrlf=false reset --hard HEAD && test -z "$(git status --porcelain)"\nRUN --mount=type=cache', 1)
    (work / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!cyclonedx-gomod\n!src/\n!src/**\n', encoding='utf-8')
    for stage in ('build', 'runtime'):
        run_command(['docker', 'build', '--platform=linux/amd64', '--target', stage,
                     '--iidfile', str(work / (stage + '.id')), str(work)], work / (stage + '.log'), timeout=1200)
    paired_hey.WORK, paired_hey.OUT, paired_hey.COMMIT = work, out, project['commit']
    paired_hey.main(project_id=project['id'], experiment='R56', recipe_path=work / 'Dockerfile')


if __name__ == '__main__':
    main()

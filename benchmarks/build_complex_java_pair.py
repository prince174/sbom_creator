"""Continue one new external reactor pair; never read its oracle in a predictor."""
import argparse
import json
import os
import shutil

from complete_dropwizard_reactor import main as complete
from complex_reactor_recipe import literal_modules, recipe
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import clean_environment
from sbom_creator.acquire import run_command as isolated_command


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', choices=['java-petclinic-microservices', 'java-vertx-web'], required=True)
    args = parser.parse_args()
    project = next(p for p in json.loads((ROOT/'benchmarks/java-js-expanded-v1.json').read_bytes())['repositories'] if p['id'] == args.project)
    namespace = 'paired-' + args.project.removeprefix('java-') + '-r104'
    work = ROOT/'benchmarks/.work'/namespace
    if (ROOT/'benchmarks/references'/namespace/'receipt.json').exists():
        raise FileExistsError('Immutable pair already complete')
    work.mkdir(parents=True, exist_ok=True)
    source = work/'src'
    environment = clean_environment()
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_TERMINAL_PROMPT='0', GIT_LFS_SKIP_SMUDGE='1')

    def git(*arguments):
        return isolated_command(['git', '-c', 'credential.helper=', '-c', 'core.autocrlf=false',
            '-c', 'core.hooksPath='+os.devnull, '-c', 'http.followRedirects=false', *arguments],
            cwd=source, env=environment, timeout=300, max_output_bytes=4096, label='Public fixture checkout')

    if not source.exists():
        source.mkdir()
        git('init', '--quiet', '--template=')
        git('remote', 'add', 'origin', project['repository_url'])
    if not (work/'checkout.json').exists():
        git('fetch', '--depth=1', '--no-tags', 'origin', project['commit'])
        git('checkout', '--detach', 'FETCH_HEAD')
        atomic_json(work/'checkout.json', {'commit': git('rev-parse', 'HEAD').strip(), 'source': project['repository_url']})
    if git('rev-parse', 'HEAD').strip() != project['commit'] or git('status', '--porcelain').strip():
        raise ValueError('Exact source differs')
    modules = literal_modules(source)
    plan = {'project': project['id'], 'commit': project['commit'], 'modules': modules,
            'profiles': 'default', 'tests': 'compiled-not-run'}
    text = recipe(modules, profile=None)
    if (work/'Dockerfile').exists() and (work/'Dockerfile').read_text(encoding='utf-8') != text:
        raise ValueError('Preserve attempted recipe')
    (work/'Dockerfile').write_text(text, encoding='utf-8', newline='\n')
    atomic_json(work/'plan.json', plan)
    shutil.copyfile(ROOT/'benchmarks/ReactorCollect.java', work/'ReactorCollect.java')
    (work/'.dockerignore').write_text('**\n!Dockerfile\n!ReactorCollect.java\n!src/\n!src/**\nsrc/.git/config\nsrc/.git/hooks/\nsrc/.git/logs/\n', encoding='utf-8')
    if not (work/'build.id').exists():
        run_command(['docker', 'build', '--platform=linux/amd64', '--target', 'build',
            '--iidfile', str(work/'build.id'), str(work)], work/'build.log', timeout=2400)
    complete(project, namespace)


if __name__ == '__main__':
    main()

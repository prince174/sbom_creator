"""Freeze and run the actual image-only service; never open build references.

Every case is serial. Both Java and JavaScript finish before the shared marker
allows the separate evaluator to open an oracle. Existing attempts are immutable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json

JAVA_CASES = {
    'microservices': ('paired-petclinic-microservices-r104',
        'sha256:0baa31188e29b4df33890b7664c46c6e8fd4c9a4ca53731db83ad05e6cb6ad95'),
    'boot': ('paired-spring-petclinic-v1', None),
    'javalin': ('paired-javalin-reactor-v1', None),
    'dropwizard': ('paired-dropwizard-reactor-v1', None),
}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def input_cases():
    """Only input archives and previously observed image identities are read."""
    cases = []
    for name, (pair, digest) in JAVA_CASES.items():
        work = ROOT / 'benchmarks/.work' / pair
        if digest is None:
            catalog = json.loads((work / 'analysis-seekable-payload-v4/image.syft.json').read_bytes())
            digest = catalog['source']['metadata']['manifestDigest']
        cases.append({'language': 'java', 'name': name, 'archive': work / 'image.tar',
                      'image': 'docker.io/library/sbom-mvp@' + digest})
    javascript = []
    for namespace in ('no-lock-v1', 'no-lock-expanded-v1'):
        for work in sorted((ROOT / 'benchmarks/.work' / namespace).glob('paired-*')):
            if not (work / 'image.tar').is_file():
                continue
            catalog = json.loads((work / 'analysis/image.syft.json').read_bytes())
            digest = catalog['source']['metadata']['manifestDigest']
            javascript.append({'language': 'javascript', 'name': work.name,
                'archive': work / 'image.tar', 'namespace': namespace,
                'image': 'docker.io/library/sbom-js-mvp@' + digest})
    if len(javascript) != 12 or len({case['name'] for case in javascript}) != 12:
        raise ValueError('All twelve unique existing no-project-lock images are required')
    return cases + javascript


def freeze(output, cases, tools, cache):
    java, javascript = output / 'java', output / 'javascript'
    java_source = java / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', java_source / 'src/sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(ROOT / 'Dockerfile', java_source / 'Dockerfile')
    (java_source / 'benchmarks').mkdir()
    shutil.copyfile(__file__, java_source / 'benchmarks/run_mvp_r106.py')
    js_source = javascript / 'executed-source'
    shutil.copytree(java_source / 'src/sbom_creator', js_source / 'sbom_creator')
    shutil.copyfile(__file__, javascript / 'executed-runner.py')
    code = sorted(p for p in java_source.rglob('*') if p.is_file())
    shared = {'oracle_read': False, 'source_input': False, 'runtime_changed': True,
              'execution_mode': 'opt-in experimental nested windows',
              'java_nested_windows': True, 'production_default_changed': False,
              'partition': 'disclosed-development-regression',
              'runner_sha256': sha(Path(__file__)),
              'tool_sha256': {name: sha(path) for name, path in tools.items()},
              'database_sha256': sha(cache / 'java-db/trivy-java.db')}
    java_freeze = {**shared, 'code_sha256': {
        p.relative_to(java_source).as_posix(): sha(p) for p in code}}
    atomic_json(java / 'freeze.json', java_freeze)
    atomic_json(javascript / 'freeze.json', {**shared, 'executed_source': 'executed-source',
        'code_sha256': {p.relative_to(js_source).as_posix(): sha(p)
                        for p in sorted(js_source.rglob('*')) if p.is_file()}})
    atomic_json(output / 'freeze.json', {**shared,
        'java_freeze_sha256': sha(java / 'freeze.json'),
        'javascript_freeze_sha256': sha(javascript / 'freeze.json'),
        'inputs': [{**{k: v for k, v in case.items() if k != 'archive'},
                    'archive': case['archive'].relative_to(ROOT).as_posix(),
                    'archive_sha256': sha(case['archive'])} for case in cases]})
    return java_source / 'src'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', default='mvp-r106-v1')
    args = parser.parse_args()
    if Path(args.run_id).name != args.run_id or not args.run_id.startswith('mvp-r106-'):
        raise ValueError('Unsafe result namespace')
    output = ROOT / 'benchmarks/results' / args.run_id
    if output.exists():
        raise FileExistsError('Preserve completed and attempted runs')
    cases = input_cases()
    tools = {'syft': ROOT / '.tools/syft/syft.exe',
             'trivy': ROOT / 'benchmarks/.work/trivy-r34/trivy.exe',
             'crane': ROOT / 'benchmarks/.work/crane-r94/crane.exe'}
    cache = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache'
    snapshot = freeze(output, cases, tools, cache)
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.pipeline import analyze

    if not Path(sys.modules['sbom_creator.pipeline'].__file__).is_relative_to(snapshot):
        raise ValueError('Runtime did not import the frozen source snapshot')
    completed = {'java': [], 'javascript': []}
    for case in cases:
        directory = output / case['language'] / case['name']
        atomic_json(directory / 'invocation.json', {
            **{k: v for k, v in case.items() if k != 'archive'},
            'archive': case['archive'].relative_to(ROOT).as_posix(),
            'archive_sha256': sha(case['archive']), 'repository_url': None, 'commit': None,
            'project_execution': False, 'oracle_read': False,
            'execution_mode': 'opt-in experimental nested windows', 'java_nested_windows': True})
        settings = Settings(syft_binary=str(tools['syft']), trivy_binary=str(tools['trivy']),
            crane_binary=str(tools['crane']), trivy_cache_dir=str(cache),
            image_archive=str(case['archive']), registry_hosts=('docker.io',),
            java_backend='disabled', java_image_evidence=True, java_nested_windows=True,
            image_temp_dir=str(ROOT / 'benchmarks/.work/mvp-r106-temporary'))
        started = time.monotonic()
        try:
            summary = analyze(None, None, case['image'], directory / 'analysis', settings)
            atomic_json(directory / 'run.json', {'status': 'completed', 'oracle_read': False,
                'elapsed_seconds': time.monotonic() - started, 'summary': summary,
                'timing': 'fresh actual pipeline; local archive registry acquisition excluded',
                'peak_rss': None})
            completed[case['language']].append(case['name'])
            print(case['language'], case['name'], 'completed', summary['final_count'], flush=True)
        except Exception as error:  # noqa: BLE001 -- retain failures without exposing credentials
            atomic_json(directory / 'run.json', {'status': 'FAILED', 'oracle_read': False,
                'elapsed_seconds': time.monotonic() - started,
                'error_type': type(error).__name__, 'error_stage': getattr(error, 'stage', None)})
            print(case['language'], case['name'], 'FAILED', type(error).__name__, flush=True)
    for language, finished in completed.items():
        requested = [case['name'] for case in cases if case['language'] == language]
        atomic_json(output / language / 'predictions-complete.json', {
            'oracle_read': False, 'cases': requested, 'completed': finished,
            'failed': sorted(set(requested) - set(finished))})
    atomic_json(output / 'predictions-complete.json', {'oracle_read': False,
        'cases': {language: [c['name'] for c in cases if c['language'] == language]
                  for language in completed}, 'completed': completed,
        'freeze_sha256': sha(output / 'freeze.json')})


if __name__ == '__main__':
    main()

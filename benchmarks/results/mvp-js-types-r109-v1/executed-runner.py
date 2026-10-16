"""Freeze and run twelve serial image-only no-lock service predictions.

Never read a component reference. Reuse immutable input images, not predictions.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json
from run_mvp_r106 import input_cases, sha


def main():
    output = ROOT / 'benchmarks/results/mvp-js-types-r109-v1'
    if output.exists():
        raise FileExistsError('Preserve all completed and attempted predictions')
    cases = [case for case in input_cases() if case['language'] == 'javascript']
    snapshot = output / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output / 'executed-runner.py')
    syft = ROOT / '.tools/syft/syft.exe'
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'fresh_scans': True,
        'fresh_physical_reads': True, 'source_input': False, 'project_execution': False,
        'java_archive_components': True, 'new_rule': 'explicit owned delivered type-surface file',
        'runner_sha256': sha(Path(__file__)), 'syft_sha256': sha(syft),
        'cases': [case['name'] for case in cases],
        'code_sha256': {p.relative_to(snapshot).as_posix(): sha(p)
                        for p in sorted(snapshot.rglob('*')) if p.is_file()},
        'input_sha256': {case['archive'].relative_to(ROOT).as_posix(): sha(case['archive'])
                         for case in cases}})
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.pipeline import analyze
    if not Path(sys.modules['sbom_creator.pipeline'].__file__).is_relative_to(snapshot):
        raise ValueError('Frozen source was not imported')
    completed, failed = [], []
    for case in cases:
        target = output / case['name']
        atomic_json(target / 'invocation.json', {**{k: v for k, v in case.items() if k != 'archive'},
            'archive': case['archive'].relative_to(ROOT).as_posix(),
            'archive_sha256': sha(case['archive']), 'oracle_read': False,
            'repository_url': None, 'commit': None, 'source_input': False,
            'fresh_scans': True, 'java_archive_components': True})
        started = time.monotonic()
        settings = Settings(syft_binary=str(syft), image_archive=str(case['archive']),
            registry_hosts=('docker.io',), java_archive_components=True,
            image_temp_dir=str(ROOT / 'benchmarks/.work/mvp-js-types-r109-temp'))
        try:
            summary = analyze(None, None, case['image'], target / 'analysis', settings)
            atomic_json(target / 'run.json', {'status': 'completed', 'oracle_read': False,
                'fresh_scans': True, 'elapsed_seconds': time.monotonic()-started, 'summary': summary,
                'timing': 'fresh pinned scanner, final-file evidence and actual publisher; local image acquisition excluded'})
            completed.append(case['name'])
            print(case['name'], 'completed', summary['final_count'], flush=True)
        except Exception as error:  # noqa: BLE001 -- safe negative evidence, never hide failures
            atomic_json(target / 'run.json', {'status': 'FAILED', 'oracle_read': False,
                'fresh_scans': True, 'elapsed_seconds': time.monotonic()-started,
                'error_type': type(error).__name__, 'stage': getattr(error, 'stage', None)})
            failed.append(case['name'])
            print(case['name'], 'FAILED', type(error).__name__, flush=True)
    for name, digest in json.loads((output / 'freeze.json').read_bytes())['code_sha256'].items():
        if sha(snapshot / name) != digest:
            raise ValueError('Executing snapshot changed')
    atomic_json(output / 'predictions-complete.json', {'oracle_read': False,
        'cases': [case['name'] for case in cases], 'completed': completed, 'failed': failed,
        'freeze_sha256': sha(output / 'freeze.json')})


if __name__ == '__main__':
    main()

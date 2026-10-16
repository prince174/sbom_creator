"""Fresh image-only runtime scans of the twelve existing no-project-lock images.

This runner enumerates existing image inputs only. It never opens reference SBOMs,
component labels, or previous accuracy reports. Source code is snapshotted before
any invocation so another task's edit cannot change the executing candidate.
"""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json

OUTPUT = ROOT / 'benchmarks/results/mvp-js-r105-v1'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve attempted JavaScript run')
    snapshot = OUTPUT / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.pipeline import analyze

    files = sorted((snapshot / 'sbom_creator').rglob('*.py'))
    syft = ROOT / '.tools/syft/syft.exe'
    shutil.copyfile(__file__, OUTPUT / 'executed-runner.py')
    atomic_json(OUTPUT / 'freeze.json', {
        'oracle_read': False, 'source_input': False,
        'code_sha256': {p.relative_to(snapshot).as_posix(): sha(p) for p in files},
        'runner_sha256': sha(Path(__file__)),
        'tool_sha256': {'syft': sha(syft)}, 'executed_source': 'executed-source'})
    cases = []
    for namespace in ('no-lock-v1', 'no-lock-expanded-v1'):
        for work in sorted((ROOT / 'benchmarks/.work' / namespace).glob('paired-*')):
            archive = work / 'image.tar'
            if not archive.is_file():
                continue
            cases.append((namespace, work))
    if len(cases) != 12:
        raise ValueError('All twelve existing no-lock images required')
    completed = []
    for namespace, work in cases:
        previous = json.loads((work / 'analysis/image.syft.json').read_bytes())
        digest = previous['source']['metadata']['manifestDigest']
        image = 'docker.io/library/sbom-js-mvp@' + digest
        directory = OUTPUT / work.name
        archive = work / 'image.tar'
        atomic_json(directory / 'invocation.json', {
            'image': image, 'archive': archive.relative_to(ROOT).as_posix(),
            'archive_sha256': sha(archive), 'repository_url': None, 'commit': None,
            'namespace': namespace, 'oracle_read': False, 'project_execution': False})
        started = time.monotonic()
        try:
            summary = analyze(None, None, image, directory / 'analysis', Settings(
                syft_binary=str(syft), registry_hosts=('docker.io',), image_archive=str(archive),
                java_backend='disabled', java_image_evidence=True))
            atomic_json(directory / 'run.json', {'status': 'completed', 'oracle_read': False,
                'elapsed_seconds': time.monotonic() - started, 'summary': summary})
            completed.append(work.name)
            print(work.name, 'completed', summary['final_count'], flush=True)
        except Exception as error:  # noqa: BLE001 -- preserve each failed service invocation
            atomic_json(directory / 'run.json', {'status': 'FAILED', 'oracle_read': False,
                'elapsed_seconds': time.monotonic() - started,
                'error_type': type(error).__name__, 'error_stage': getattr(error, 'stage', None)})
            print(work.name, 'FAILED', type(error).__name__, flush=True)
    names = [work.name for _, work in cases]
    atomic_json(OUTPUT / 'predictions-complete.json', {
        'oracle_read': False, 'cases': names, 'completed': completed,
        'failed': sorted(set(names) - set(completed))})


if __name__ == '__main__':
    main()

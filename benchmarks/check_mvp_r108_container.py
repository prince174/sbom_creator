"""Freeze, build and run the installed R108 image-only Linux pipeline.

Inputs are the supplied image archive and public scanner DB only. This command
never opens a reference SBOM and deliberately reports no accuracy metrics.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import subprocess
import sys
import time
from datetime import UTC, datetime


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, document):
    path.write_text(json.dumps(document, indent=2)+'\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path,
                        default=pathlib.Path('benchmarks/results/mvp-r108-container-v1'))
    parser.add_argument('--nested-windows', action='store_true',
                        help='Explicitly enable the experimental reader; the default remains stable.')
    parser.add_argument('--archive-components', action='store_true',
                        help='Explicitly enable delivered archive components; default remains stable.')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    harness = output/'executed-harness'
    harness.mkdir()
    for script in (pathlib.Path(__file__), root/'benchmarks/smoke_mvp_container.py'):
        (harness/script.name).write_bytes(script.read_bytes())
    archive = root/'benchmarks/.work/paired-petclinic-microservices-r104/image.tar'
    database = root/'benchmarks/.work/trivy-reactor-image-v1/cache/java-db'
    files = [root/'Dockerfile', root/'.dockerignore', root/'pyproject.toml',
        *(p for p in sorted((root/'src').rglob('*')) if p.is_file()
          and '__pycache__' not in p.parts and p.suffix != '.pyc')]
    hashes = {p.relative_to(root).as_posix(): sha(p) for p in files}
    recorded = root/'benchmarks/results/mvp-r108-v1/executed-source/sbom_creator'
    recorded_hashes = {p.relative_to(recorded).as_posix(): sha(p)
                       for p in sorted(recorded.rglob('*')) if p.is_file()
                       and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    package_hashes = {k.removeprefix('src/sbom_creator/'): v for k, v in hashes.items()
                      if k.startswith('src/sbom_creator/')}
    assert len(package_hashes) == 47 and package_hashes == recorded_hashes
    freeze = {'frozen_at': datetime.now(UTC).isoformat(),
        'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'source_hashes': hashes, 'predictor_script_sha256': sha(pathlib.Path(__file__)),
        'smoke_script_sha256': sha(root/'benchmarks/smoke_mvp_container.py'),
        'inputs': {'archive': {'path': str(archive), 'bytes': archive.stat().st_size,
                             'sha256': sha(archive)},
                   'public_java_db': {'bytes': (database/'trivy-java.db').stat().st_size,
                                      'sha256': sha(database/'trivy-java.db')},
                   'public_java_db_metadata_sha256': sha(database/'metadata.json')},
        'reference_accessed': False, 'source_repository_input': False,
        'java_nested_windows_requested': args.nested_windows,
        'java_archive_components_requested': args.archive_components,
        'classifier_snapshot_equals_parent_frozen_source': True,
        'image_reference': 'docker.io/library/microservices@sha256:'
            '0baa31188e29b4df33890b7664c46c6e8fd4c9a4ca53731db83ad05e6cb6ad95'}
    write(output/'candidate-freeze.json', freeze)
    command = ['docker', 'build', '--progress=plain', '--tag', 'sbom-creator:mvp-r108', '.']
    started = time.monotonic()
    with (output/'build.log').open('wb') as log:
        built = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                               check=False, timeout=900)
    changed = {p.relative_to(root).as_posix(): sha(p) for p in files
               if hashes[p.relative_to(root).as_posix()] != sha(p)}
    build = {'exit_code': built.returncode, 'elapsed_seconds': round(time.monotonic()-started, 3),
             'command': command, 'source_changed_during_build': changed}
    if built.returncode == 0:
        build['image'] = json.loads(subprocess.check_output(
            ['docker', 'image', 'inspect', 'sbom-creator:mvp-r108']))[0]
    write(output/'build.json', build)
    if built.returncode or changed:
        print(json.dumps({k: v for k, v in build.items() if k != 'image'}, indent=2))
        return built.returncode or 2
    smoke_command = [sys.executable, str(root/'benchmarks/smoke_mvp_container.py'),
        '--image', build['image']['Id'], '--archive', str(archive), '--java-db', str(database),
        '--image-reference', freeze['image_reference'], '--output', str(output/'microservices')]
    if args.nested_windows:
        smoke_command.append('--nested-windows')
    if args.archive_components:
        smoke_command.append('--archive-components')
    with (output/'smoke-host.log').open('wb') as log:
        smoked = subprocess.run(smoke_command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                check=False, timeout=1500)
    smoke = output/'microservices'
    report = {'exit_code': smoked.returncode, 'image_id': build['image']['Id'],
        'java_nested_windows_requested': args.nested_windows,
        'java_archive_components_requested': args.archive_components,
        'source_hashes_unchanged_after_prediction':
            all(hashes[p.relative_to(root).as_posix()] == sha(p) for p in files),
        'public_java_db_unchanged': freeze['inputs']['public_java_db']['sha256']
            == sha(database/'trivy-java.db'),
        'reference_accessed': False, 'accuracy': 'not-evaluated; oracle access is post-analysis only'}
    environment = smoke/'workspace/environment.json'
    if environment.is_file():
        installed = json.loads(environment.read_text())['installed_source_hashes']
        expected = {k.removeprefix('src/sbom_creator/'): v for k, v in hashes.items()
                    if k.startswith('src/sbom_creator/')}
        report['installed_source_and_data_equal_frozen_snapshot'] = installed == expected
        report['installed_file_count'] = len(installed)
    result = smoke/'workspace/smoke-result.json'
    if result.is_file():
        report['pipeline'] = json.loads(result.read_text())
    audit = smoke/'workspace/analysis/image-identity-audit.json'
    if audit.is_file():
        parsed = json.loads(audit.read_text())
        report['physical_read_resources'] = {key: parsed.get(key) for key in
                                             ('jar_resources', 'layer_resources')}
    manifest = smoke/'artifact-manifest.json'
    if manifest.is_file():
        exported = json.loads(manifest.read_text())
        for entry in exported.values():
            stored = (smoke/entry['file']).read_bytes()
            raw = gzip.decompress(stored) if entry['file'].endswith('.gz') else stored
            assert hashlib.sha256(stored).hexdigest() == entry['stored_sha256']
            assert hashlib.sha256(raw).hexdigest() == entry['original_sha256']
            json.loads(raw)
        report['verified_exported_artifacts'] = len(exported)
    write(output/'verification.json', report)
    print(json.dumps(report, indent=2))
    return smoked.returncode


if __name__ == '__main__':
    raise SystemExit(main())

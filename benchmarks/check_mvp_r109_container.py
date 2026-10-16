"""Build and verify the installed npm declared-type feature without oracle input."""
from __future__ import annotations

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
    path.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    output = root / 'benchmarks/results/mvp-r109-container-v1'
    output.mkdir(parents=True, exist_ok=False)
    harness = output / 'executed-harness'
    harness.mkdir()
    for script in (pathlib.Path(__file__), root / 'benchmarks/smoke_mvp_container.py'):
        (harness / script.name).write_bytes(script.read_bytes())
    invocation_path = root / 'benchmarks/results/mvp-r106-v1/javascript/paired-nest-starter-v1/invocation.json'
    invocation = json.loads(invocation_path.read_bytes())
    archive = root / invocation['archive']
    if sha(archive) != invocation['archive_sha256']:
        raise ValueError('Supplied immutable image archive changed')
    database = root / 'benchmarks/.work/trivy-reactor-image-v1/cache/java-db'
    files = [root / 'Dockerfile', root / '.dockerignore', root / 'pyproject.toml',
             *(p for p in sorted((root / 'src').rglob('*')) if p.is_file()
               and '__pycache__' not in p.parts and p.suffix != '.pyc')]
    hashes = {p.relative_to(root).as_posix(): sha(p) for p in files}
    parent_freeze = root / 'benchmarks/results/mvp-js-types-r109-v1/freeze.json'
    frozen = json.loads(parent_freeze.read_bytes())
    expected_package = {k.removeprefix('sbom_creator/'): v for k, v in frozen['code_sha256'].items()}
    package_hashes = {k.removeprefix('src/sbom_creator/'): v for k, v in hashes.items()
                      if k.startswith('src/sbom_creator/')}
    if len(package_hashes) != 47 or package_hashes != expected_package:
        raise ValueError('Installed candidate must equal the parent frozen source and data')
    freeze = {'frozen_at': datetime.now(UTC).isoformat(),
        'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'source_hashes': hashes, 'driver_sha256': sha(pathlib.Path(__file__)),
        'smoke_script_sha256': sha(root / 'benchmarks/smoke_mvp_container.py'),
        'parent_freeze_sha256': sha(parent_freeze), 'invocation_sha256': sha(invocation_path),
        'inputs': {'archive': {'path': archive.relative_to(root).as_posix(),
                              'sha256': sha(archive), 'bytes': archive.stat().st_size},
                   'public_java_db': {'sha256': sha(database / 'trivy-java.db'),
                                      'bytes': (database / 'trivy-java.db').stat().st_size},
                   'public_java_db_metadata_sha256': sha(database / 'metadata.json')},
        'reference_accessed': False, 'repository_input': False,
        'classifier_snapshot_equals_parent_frozen_source': True,
        'mode': 'actual installed image-only JavaScript pipeline; no project lockfiles',
        'java_archive_components_requested': False, 'java_nested_windows_requested': False,
        'image_reference': invocation['image']}
    write(output / 'candidate-freeze.json', freeze)
    command = ['docker', 'build', '--progress=plain', '--tag', 'sbom-creator:mvp-r109', '.']
    started = time.monotonic()
    with (output / 'build.log').open('wb') as log:
        built = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                               check=False, timeout=900)
    changed = {p.relative_to(root).as_posix(): sha(p) for p in files
               if hashes[p.relative_to(root).as_posix()] != sha(p)}
    build = {'exit_code': built.returncode, 'elapsed_seconds': round(time.monotonic() - started, 3),
             'command': command, 'source_changed_during_build': changed}
    if built.returncode == 0:
        build['image'] = json.loads(subprocess.check_output(
            ['docker', 'image', 'inspect', 'sbom-creator:mvp-r109']))[0]
    write(output / 'build.json', build)
    if built.returncode or changed:
        return built.returncode or 2
    smoke_command = [sys.executable, str(root / 'benchmarks/smoke_mvp_container.py'),
        '--image', build['image']['Id'], '--archive', str(archive), '--java-db', str(database),
        '--image-reference', freeze['image_reference'], '--language', 'javascript',
        '--output', str(output / 'nest')]
    with (output / 'smoke-host.log').open('wb') as log:
        smoked = subprocess.run(smoke_command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                check=False, timeout=1500)
    smoke = output / 'nest'
    report = {'exit_code': smoked.returncode, 'image_id': build['image']['Id'],
        'source_hashes_unchanged_after_prediction':
            all(hashes[p.relative_to(root).as_posix()] == sha(p) for p in files),
        'public_java_db_unchanged': freeze['inputs']['public_java_db']['sha256']
            == sha(database / 'trivy-java.db'),
        'reference_accessed': False, 'accuracy': 'not-evaluated; post-analysis only'}
    environment = smoke / 'workspace/environment.json'
    if environment.is_file():
        facts = json.loads(environment.read_bytes())
        report['installed_source_and_data_equal_frozen_snapshot'] = (
            facts['installed_source_hashes'] == expected_package)
        report['installed_file_count'] = len(facts['installed_source_hashes'])
        report['java_modes_remain_default_false'] = (
            facts['java_archive_components'] is False and facts['java_nested_windows'] is False)
    result = smoke / 'workspace/smoke-result.json'
    if result.is_file():
        report['pipeline'] = json.loads(result.read_bytes())
    manifest = smoke / 'artifact-manifest.json'
    if manifest.is_file():
        exported = json.loads(manifest.read_bytes())
        for entry in exported.values():
            stored = (smoke / entry['file']).read_bytes()
            raw = gzip.decompress(stored) if entry['file'].endswith('.gz') else stored
            if (hashlib.sha256(stored).hexdigest() != entry['stored_sha256']
                    or hashlib.sha256(raw).hexdigest() != entry['original_sha256']):
                raise ValueError('Container artifact export hash mismatch')
            json.loads(raw)
        report['verified_exported_artifacts'] = len(exported)
    write(output / 'verification.json', report)
    print(json.dumps(report, indent=2))
    return smoked.returncode


if __name__ == '__main__':
    raise SystemExit(main())

"""One installed default-config REST pipeline, isolated and without reference inputs.

The parent Windows freeze supplies only code/input binding, never a reference
SBOM or expected component. Parity is a separate post-prediction command.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, document):
    Path(path).write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')


def package_hashes(code):
    result = {}
    for name, value in code.items():
        if '__pycache__' in Path(name).parts or name.endswith('.pyc'):
            continue
        if name.startswith('src/sbom_creator/'):
            result[name.removeprefix('src/sbom_creator/')] = value
        elif name.startswith('sbom_creator/'):
            result[name.removeprefix('sbom_creator/')] = value
    if len(result) != 47:
        raise ValueError('Exactly 47 frozen installed package/data files are required')
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-output', type=Path,
                        default=root / 'benchmarks/results/mvp-r110-held-controls-v1')
    parser.add_argument('--output', type=Path,
                        default=root / 'benchmarks/results/mvp-r110-container-v1')
    args = parser.parse_args()
    parent, output = args.parent_output.resolve(), args.output.resolve()
    if output.exists():
        raise FileExistsError('Preserve every attempted installed pipeline namespace')
    parent_freeze = parent / 'freeze.json'
    frozen = json.loads(parent_freeze.read_bytes())
    expected_package = package_hashes(frozen['code_sha256'])
    invocation_path = parent / 'rest/invocation.json'
    invocation = json.loads(invocation_path.read_bytes())
    if (invocation.get('oracle_read') is not False or invocation.get('source_input') is not False
            or invocation.get('repository_url') is not None or invocation.get('commit') is not None
            or invocation.get('java_archive_components_default') is not True
            or invocation.get('java_archive_components_override_supplied') is not False):
        raise ValueError('Parent REST invocation must be image-only and use the actual Java default')
    archive = (root / invocation['archive']).resolve()
    expected_archive = root / 'benchmarks/.work/paired-petclinic-rest-v1/image.tar'
    if archive != expected_archive.resolve() or sha(archive) != invocation['archive_sha256']:
        raise ValueError('Use only the existing immutable REST input image')
    files = [root / 'Dockerfile', root / '.dockerignore', root / 'pyproject.toml',
             *(path for path in sorted((root / 'src').rglob('*')) if path.is_file()
               and '__pycache__' not in path.parts and path.suffix != '.pyc')]
    hashes = {path.relative_to(root).as_posix(): sha(path) for path in files}
    current_package = package_hashes(hashes)
    if current_package != expected_package:
        raise ValueError('Current package differs from the frozen Windows control candidate')
    database = root / 'benchmarks/.work/trivy-reactor-image-v1/cache/java-db'
    database_hash = sha(database / 'trivy-java.db')
    db_key = (database / 'trivy-java.db').relative_to(root).as_posix()
    pinned_db_hash = frozen.get('database_sha256') or frozen.get('input_sha256', {}).get(db_key)
    if pinned_db_hash != database_hash:
        raise ValueError('Windows and installed public database bytes differ')
    output.mkdir(parents=True)
    harness = output / 'executed-harness'
    harness.mkdir()
    for script in (Path(__file__), root / 'benchmarks/smoke_mvp_container.py'):
        (harness / script.name).write_bytes(script.read_bytes())
    freeze = {'frozen_at': datetime.now(UTC).isoformat(),
        'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'source_hashes': hashes, 'driver_sha256': sha(Path(__file__)),
        'smoke_script_sha256': sha(root / 'benchmarks/smoke_mvp_container.py'),
        'parent_freeze_sha256': sha(parent_freeze), 'parent_invocation_sha256': sha(invocation_path),
        'expected_installed_hashes': expected_package,
        'inputs': {'archive': {'path': archive.relative_to(root).as_posix(),
                              'sha256': sha(archive), 'bytes': archive.stat().st_size},
                   'public_java_db': {'sha256': database_hash,
                                      'bytes': (database / 'trivy-java.db').stat().st_size},
                   'public_java_db_metadata_sha256': sha(database / 'metadata.json')},
        'reference_accessed': False, 'repository_input': False,
        'mode': 'actual installed default-config Java REST pipeline',
        'reader_environment_overrides_supplied': False,
        'expected_java_archive_components_default': True,
        'expected_java_nested_windows_default': False,
        'image_reference': invocation['image']}
    write(output / 'candidate-freeze.json', freeze)
    command = ['docker', 'build', '--progress=plain', '--tag', 'sbom-creator:mvp-r110', '.']
    started = time.monotonic()
    with (output / 'build.log').open('wb') as log:
        built = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                               check=False, timeout=900)
    changed = {path.relative_to(root).as_posix(): sha(path) for path in files
               if hashes[path.relative_to(root).as_posix()] != sha(path)}
    build = {'exit_code': built.returncode, 'elapsed_seconds': round(time.monotonic() - started, 3),
             'command': command, 'source_changed_during_build': changed}
    if built.returncode == 0:
        build['image'] = json.loads(subprocess.check_output(
            ['docker', 'image', 'inspect', 'sbom-creator:mvp-r110']))[0]
    write(output / 'build.json', build)
    if built.returncode or changed:
        return built.returncode or 2
    configured_env = {entry.split('=', 1)[0] for entry in build['image']['Config'].get('Env', [])}
    if configured_env & {'SBOM_JAVA_ARCHIVE_COMPONENTS', 'SBOM_JAVA_NESTED_WINDOWS'}:
        raise ValueError('Docker ENV must not impersonate the Python reader defaults')
    smoke_command = [sys.executable, str(root / 'benchmarks/smoke_mvp_container.py'),
        '--image', build['image']['Id'], '--archive', str(archive), '--java-db', str(database),
        '--image-reference', freeze['image_reference'], '--language', 'java', '--reader-defaults',
        '--output', str(output / 'rest')]
    with (output / 'smoke-host.log').open('wb') as log:
        smoked = subprocess.run(smoke_command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                check=False, timeout=1500)
    smoke = output / 'rest'
    report = {'exit_code': smoked.returncode, 'image_id': build['image']['Id'],
        'source_hashes_unchanged_after_prediction':
            all(hashes[path.relative_to(root).as_posix()] == sha(path) for path in files),
        'public_java_db_unchanged': database_hash == sha(database / 'trivy-java.db'),
        'reference_accessed': False, 'accuracy': 'not-evaluated; post-analysis only',
        'reader_environment_overrides_supplied': False, 'docker_env_reader_overrides_absent': True}
    environment = smoke / 'workspace/environment.json'
    if environment.is_file():
        facts = json.loads(environment.read_bytes())
        report['installed_source_and_data_equal_frozen_snapshot'] = (
            facts['installed_source_hashes'] == expected_package)
        report['installed_file_count'] = len(facts['installed_source_hashes'])
        report['default_java_archive_components_true_nested_windows_false'] = (
            facts['java_archive_components'] is True and facts['java_nested_windows'] is False
            and facts.get('reader_defaults_requested') is True
            and all(value is None for value in facts.get('reader_environment_values', {}).values())
            and set(facts.get('reader_environment_values', {})) == {
                'SBOM_JAVA_ARCHIVE_COMPONENTS', 'SBOM_JAVA_NESTED_WINDOWS'})
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
    required = ('installed_source_and_data_equal_frozen_snapshot', 'source_hashes_unchanged_after_prediction',
                'public_java_db_unchanged', 'default_java_archive_components_true_nested_windows_false')
    report['status'] = 'passed' if smoked.returncode == 0 and all(report.get(key) is True for key in required) else 'failed'
    write(output / 'verification.json', report)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else smoked.returncode or 2


if __name__ == '__main__':
    raise SystemExit(main())

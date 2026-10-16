"""One installed R112 warm DBCP run, with retained public DB and no downloads.

This reuses the R111 warm pipeline program and export helpers. Its program is a
read-only mounted file, not a Windows-quoted ``python -c`` argument. No reference
or source repository is read; parity compares already sealed host predictions.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import check_mvp_r111_cold_cache as previous

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r112-container-v1'
PREDICTIONS = ROOT / 'benchmarks/results/mvp-r112-java-v1'
DB_SHA = '491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59'
METADATA_SHA = '40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2'

GUARD = r'''
from sbom_creator.image_java import runtime
with database.open('rb') as stream:
    database_before_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
metadata_before_sha256 = hashlib.sha256(metadata.read_bytes()).hexdigest()
assert database_before_sha256 == os.environ['R112_DB_SHA256']
assert metadata_before_sha256 == os.environ['R112_METADATA_SHA256']
original_ensure = runtime.ensure_database
download_attempts = []
def no_download(_stage):
    download_attempts.append('forbidden')
    raise AssertionError('Warm installed check forbids the downloader callback')
def warm_ensure(cache, _downloader):
    return original_ensure(cache, no_download)
runtime.ensure_database = warm_ensure
original_command = runtime.run_command
def guarded_command(args, **kwargs):
    if '--download-java-db-only' in args:
        raise AssertionError('Warm installed check forbids database downloads')
    if args[1] != 'version':
        assert args[1] == 'image'
        assert all(flag in args for flag in ('--input','--offline-scan','--skip-db-update',
                                            '--skip-java-db-update','--skip-version-check'))
    return original_command(args, **kwargs)
runtime.run_command = guarded_command
'''


def program():
    """Keep the measured R111 pipeline checks; change only this warm job scope."""
    value = previous.PROGRAM.replace('R111_', 'R112_')
    before = "root = pathlib.Path('/workspace')"
    assert value.count(before) == 1
    value = value.replace(before, "root = pathlib.Path(os.environ['R112_RUN_DIRECTORY'])\nroot.mkdir()")
    assert value.count("assert phase in ('cold', 'warm')") == 1
    value = value.replace("assert phase in ('cold', 'warm')", "assert phase == 'warm'")
    token = "tool_hashes = {name:"
    assert value.count(token) == 1
    value = value.replace(token, GUARD + '\n' + token)
    token = "(root / (phase + '-environment.json')).write_text"
    assert value.count(token) == 1
    value = value.replace(token, "facts.update(database_sha256_before_pipeline=database_before_sha256, "
        + "metadata_sha256_before_pipeline=metadata_before_sha256, "
        + "executed_program_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())\n" + token)
    token = "assert engine['database_sha256'] == observed_hash"
    assert value.count(token) == 1
    value = value.replace(token, token + "\n    assert observed_hash == os.environ['R112_DB_SHA256']"
        + "\n    assert engine['java_database_download_seconds'] == 0"
        + "\n    assert not download_attempts"
        + "\n    assert hashlib.sha256(metadata.read_bytes()).hexdigest() == os.environ['R112_METADATA_SHA256']")
    return value


def command(image, archive, harness, volume, job, invocation, hashes, name):
    if not previous.IMAGE_ID.fullmatch(image) or not re.fullmatch(r'sbom-r111-public-java-[0-9]+', volume):
        raise ValueError('Pinned image and exact retained R111 cache volume required')
    if not re.fullmatch(r'/workspace/r112-warm-[0-9]+', job):
        raise ValueError('One private new warm job directory required')
    return ['docker', 'run', '--name', name, '--pull=never', '--no-healthcheck', '--network=none',
        '--read-only', '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--memory=3g', '--cpus=2', '--pids-limit=128',
        '--tmpfs=/tmp:rw,nosuid,nodev,size=512m,mode=1777',
        '--mount', f'type=bind,src={archive},dst=/inputs/image.tar,readonly',
        '--mount', f'type=bind,src={harness},dst=/harness/program.py,readonly',
        '--mount', f'type=volume,src={volume},dst=/workspace',
        '--env', 'R112_PHASE=warm', '--env', 'R112_RUN_DIRECTORY=' + job,
        '--env', 'R112_IMAGE_REFERENCE=' + invocation['image'],
        '--env', 'R112_EXPECTED_IMAGE_CONFIG=' + invocation['previously_observed_config_digest'],
        '--env', 'R112_EXPECTED_PACKAGE_HASHES=' + json.dumps(hashes, sort_keys=True, separators=(',', ':')),
        '--env', 'R112_DB_SHA256=' + DB_SHA, '--env', 'R112_METADATA_SHA256=' + METADATA_SHA,
        '--entrypoint=python', image, '/harness/program.py']


def inspect(name, environment):
    item = json.loads(subprocess.check_output(['docker', 'container', 'inspect', name], env=environment))[0]
    return {'image_id': item['Image'], 'path': item['Path'], 'args': item['Args'],
        'config': item['Config'], 'host_config': item['HostConfig'], 'mounts': item['Mounts'],
        'state': item['State']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root-all-six-ready', action='store_true')
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    if not args.root_all_six_ready:
        raise ValueError('Explicit root ALL6READY required before build or Docker access')
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError('Preserve every attempted installed check; no automatic retry')
    marker = previous.json.loads((PREDICTIONS / 'predictions-complete.json').read_bytes())
    frozen = previous.json.loads((PREDICTIONS / 'freeze.json').read_bytes())
    if (marker.get('oracle_read') is not False or marker.get('completed') != list(frozen['cases'])
            or marker.get('failed') or marker.get('freeze_sha256') != previous.sha(PREDICTIONS / 'freeze.json')
            or marker.get('all_frozen_source_tool_database_image_catalog_inputs_unchanged') is not True):
        raise ValueError('All six sealed successful host predictions required')
    invocation = json.loads((PREDICTIONS / 'dbcp/invocation.json').read_bytes())
    archive = ROOT / invocation['archive']
    if (invocation['oracle_read'] is not False or previous.sha(archive) != invocation['archive_sha256']
            or invocation['database_sha256'] != DB_SHA or invocation['database_metadata_sha256'] != METADATA_SHA):
        raise ValueError('Sealed observed DBCP/public DB inputs differ')
    volume = json.loads((ROOT / 'benchmarks/results/mvp-r111-cold-cache-v2/volume.json').read_bytes())['name']
    source = ROOT / 'src/sbom_creator'
    hashes = {path.relative_to(source).as_posix(): previous.sha(path) for path in sorted(source.rglob('*'))
              if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    if len(hashes) != 48 or {'sbom_creator/' + name: value for name, value in hashes.items()} != frozen['code_sha256']:
        raise ValueError('Current 48 installed source/schema bytes must equal six-case freeze')
    environment = previous.host_environment()
    output.mkdir(parents=True)
    shutil.copyfile(__file__, output / 'executed-harness.py')
    shutil.copyfile(previous.__file__, output / 'executed-r111-helper.py')
    harness = output / 'container-program.py'
    harness.write_text(program(), encoding='utf-8', newline='\n')
    snapshot = output / 'executed-source/sbom_creator'
    for name in hashes:
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    build_files = {name: previous.sha(ROOT / name) for name in ('Dockerfile', '.dockerignore', 'pyproject.toml')}
    freeze = {'frozen_at': datetime.now(UTC).isoformat(), 'reference_accessed': False,
        'source_sha256': hashes, 'build_file_sha256': build_files, 'public_database_sha256': DB_SHA,
        'public_metadata_sha256': METADATA_SHA, 'retained_public_cache_volume': volume,
        'host_prediction_marker_sha256': previous.sha(PREDICTIONS / 'predictions-complete.json'),
        'harness_sha256': previous.sha(__file__), 'r111_helper_sha256': previous.sha(previous.__file__),
        'container_program_sha256': previous.sha(harness), 'input': invocation,
        'host_environment_names': sorted(environment), 'database_download_permitted': False}
    previous.write(output / 'freeze.json', freeze)
    started = time.monotonic()
    build_command = ['docker', 'build', '--progress=plain', '--tag', 'sbom-creator:mvp-r112', '.']
    with (output / 'build.log').open('wb') as log:
        built = subprocess.run(build_command, cwd=ROOT, env=environment, stdout=log,
            stderr=subprocess.STDOUT, check=False, timeout=900)
    unchanged = (all(previous.sha(source / name) == value for name, value in hashes.items())
                 and all(previous.sha(ROOT / name) == value for name, value in build_files.items()))
    previous.write(output / 'build.json', {'exit_code': built.returncode,
        'seconds': time.monotonic() - started, 'command': build_command, 'frozen_source_unchanged': unchanged})
    if built.returncode or not unchanged:
        return 2
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', 'sbom-creator:mvp-r112'],
                                             env=environment))[0]
    previous.write(output / 'built-image.json', image)
    image_id = image['Id']
    if any(entry.split('=', 1)[0] in {'SBOM_JAVA_ARCHIVE_COMPONENTS', 'SBOM_JAVA_NESTED_WINDOWS'}
           for entry in image['Config'].get('Env', [])):
        raise ValueError('Feature environment override may not impersonate defaults')
    suffix = str(time.time_ns())
    job, name = '/workspace/r112-warm-' + suffix, 'sbom-r112-warm-' + suffix
    invocation_command = command(image_id, archive, harness, volume, job, invocation, hashes, name)
    started = time.monotonic()
    with (output / 'container.log').open('wb') as log:
        try:
            completed = subprocess.run(invocation_command, env=environment, stdout=log,
                stderr=subprocess.STDOUT, check=False, timeout=300)
            code = completed.returncode
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'kill', name], env=environment, stdout=log,
                           stderr=subprocess.STDOUT, check=False, timeout=30)
            code = 124
    elapsed = time.monotonic() - started
    inspected = inspect(name, environment)
    previous.write(output / 'container-inspect.json', inspected)
    copied = {target: previous.copy_from(name, job + '/' + origin, output / target, environment)
              for origin, target in (('warm-environment.json', 'environment.json'),
                                     ('warm-result.json', 'result.json'), ('analysis-warm', 'analysis'))}
    subprocess.run(['docker', 'rm', name], env=environment, capture_output=True, check=False, timeout=30)
    exported = previous.export_analysis(output)
    exports = previous.verify_exports(output, exported)
    result = json.loads((output / 'result.json').read_bytes()) if copied['result.json'] else None
    facts = json.loads((output / 'environment.json').read_bytes()) if copied['environment.json'] else {}
    parity = {}
    if copied['analysis']:
        for view in ('final', 'os', 'full'):
            actual = json.loads((output / 'analysis' / (view + '.cdx.json')).read_bytes())
            expected = json.loads((PREDICTIONS / 'dbcp/analysis' / (view + '.cdx.json')).read_bytes())
            parity[view] = previous.coordinates(actual) == previous.coordinates(expected)
        actual_ids = {row['id'] for row in json.loads((output / 'analysis/selected.syft.json').read_bytes())['artifacts']}
        expected_ids = {row['id'] for row in json.loads((PREDICTIONS / 'dbcp/analysis/selected.syft.json').read_bytes())['artifacts']}
        parity['selected_ids'] = actual_ids == expected_ids
    actual_command = (inspected['path'] == 'python' and inspected['args'] == ['/harness/program.py']
        and inspected['config']['Cmd'] == ['/harness/program.py']
        and inspected['config']['Entrypoint'] == ['python']
        and facts.get('executed_program_sha256') == previous.sha(harness))
    unchanged = all(previous.sha(source / name) == value for name, value in hashes.items())
    report = {'status': 'passed' if code == 0 and result and result['status'] == 'passed'
        and all(copied.values()) and exported and all(exports.values()) and all(parity.values())
        and actual_command and unchanged else 'failed',
        'exit_code': code, 'image_id': image_id, 'container_seconds': elapsed, 'result': result,
        'export_success': copied, 'compressed_exports_verified': exports,
        'same_host_dbcp_coordinate_instances': parity, 'actual_cmd_args_verified': actual_command,
        'mounted_program_sha256': previous.sha(harness), 'original_source_unchanged': unchanged,
        'container_flags': invocation_command[1:invocation_command.index(image_id)],
        'reference_accessed': False, 'source_input': False, 'database_download_attempts': 0,
        'accuracy': 'not evaluated; installed warm pipeline and host-output regression only'}
    previous.write(output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'image_id': image_id, 'container_seconds': elapsed}))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())

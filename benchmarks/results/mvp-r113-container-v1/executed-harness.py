"""One installed cached-Nest publisher check; no scanner, reader or Java DB.

Only three retained R109 raw/evidence JSON documents enter the restricted job.
Expected SBOMs and selected IDs stay on the host until after job export.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import check_mvp_r111_cold_cache as utilities
from check_mvp_r112_container import inspect

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r113-container-v1'
HOST = ROOT / 'benchmarks/results/mvp-r113-publication-v1'
INPUTS = ROOT / 'benchmarks/results/mvp-js-types-r109-v1/paired-nest-starter-v1/analysis'
NAMES = ('source.syft.json', 'image.syft.json', 'provenance.json')
VIEWS = ('final', 'os', 'full')

PROGRAM = r'''
import hashlib, json, os, pathlib, time
import sbom_creator
from sbom_creator import acquire, build_backend, payload, pipeline, scanner
from sbom_creator.acquire import Settings
from sbom_creator.image_java import runtime, java_database_cache
from sbom_creator.validation import validate_cyclonedx

root = pathlib.Path('/workspace')
assert os.geteuid() == 10001 and not pathlib.Path('/var/run/docker.sock').exists()
assert not any(root.iterdir()), 'One new native workspace volume is required'
assert not any(os.environ.get(name) for name in (
    'SBOM_API_TOKEN','SBOM_API_TOKEN_FILE','SBOM_REGISTRY_USERNAME','SBOM_REGISTRY_PASSWORD',
    'SBOM_REGISTRY_USERNAME_FILE','SBOM_REGISTRY_PASSWORD_FILE','OPENAI_API_KEY','GITHUB_TOKEN',
    'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'))
try:
    pathlib.Path('/root-write-probe').write_text('blocked')
except OSError:
    pass
else:
    raise AssertionError('Root filesystem must be read only')
package = pathlib.Path(sbom_creator.__file__).parent
installed = {path.relative_to(package).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(package.rglob('*')) if path.is_file()
             and '__pycache__' not in path.parts and path.suffix != '.pyc'}
assert len(installed) == 49 and installed == json.loads(os.environ['R113_PACKAGE_HASHES'])
names = ('source.syft.json','image.syft.json','provenance.json')
input_hashes = {name:hashlib.sha256((pathlib.Path('/inputs')/name).read_bytes()).hexdigest() for name in names}
assert input_hashes == json.loads(os.environ['R113_INPUT_HASHES'])
source, image, provenance = (json.loads((pathlib.Path('/inputs')/name).read_bytes()) for name in names)
assert not source['artifacts'] and not source.get('artifactRelationships')
assert provenance['source_kind'] == 'not-provided'
assert provenance.get('request',{}).get('repository_url') is None
assert provenance.get('request',{}).get('commit') is None
original_payload = provenance['image']['payload_evidence']
assert any(fact.get('payload_kind') == 'declared_type_surface' for fact in original_payload.values())
defaults = Settings.from_env()
assert defaults.java_archive_components is True and defaults.java_nested_windows is False
assert defaults.java_backend == 'disabled'
assert 'SBOM_JAVA_ARCHIVE_COMPONENTS' not in os.environ and 'SBOM_JAVA_NESTED_WINDOWS' not in os.environ

def forbidden(*_args, **_kwargs):
    raise AssertionError('Only cached publication and pinned Syft conversion are permitted')
for module, name in ((acquire,'checkout'),(build_backend,'resolve'),(payload,'collect'),
    (scanner,'scan_source'),(scanner,'scan_image'),(scanner,'collect_payload'),
    (pipeline,'checkout'),(pipeline,'scan_source'),(pipeline,'scan_image'),(pipeline,'resolve_java'),
    (runtime,'acquire'),(runtime,'peer'),(runtime,'analyze'),(runtime,'corroborate'),
    (runtime,'ensure_database'),(runtime,'PublicJavaHashLookup'),(java_database_cache,'ensure')):
    setattr(module,name,forbidden)
original_syft, conversions = scanner._syft, []
def convert_only(args, settings, *, output):
    assert args[0] == 'convert'
    conversions.append('convert')
    return original_syft(args, settings, output=output)
scanner._syft = convert_only
facts = {'uid':os.geteuid(),'root_read_only':True,'docker_socket_present':False,
    'installed_source_hashes':installed,'input_sha256':input_hashes,
    'executed_program_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    'java_archive_components_default':defaults.java_archive_components,
    'java_nested_windows_default':defaults.java_nested_windows,'feature_overrides_absent':True,
    'cached_payload_mapping':True,'fresh_scans':False,'fresh_physical_reads':False,'source_project_input':False,
    'reference_accessed':False,'database_read_or_downloaded':False}
(root/'environment.json').write_text(json.dumps(facts,indent=2)+'\n')
started = time.monotonic()
result = {'status':'failed','reference_accessed':False,'new_accuracy_measurement':False}
try:
    summary = pipeline.publish_catalogs(source,image,root/'analysis',defaults,pipeline.rules_assessor,provenance)
    assert conversions == ['convert'] and summary['policy_version'] == 'image-evidence-and-payload-v4'
    for view in ('final','os','full'):
        validate_cyclonedx(json.loads((root/'analysis'/(view+'.cdx.json')).read_bytes()))
    actual = json.loads((root/'analysis/provenance.json').read_bytes())['image']['payload_evidence']
    assert actual == original_payload
    assert not pathlib.Path(defaults.trivy_cache_dir).exists()
    assert input_hashes == {name:hashlib.sha256((pathlib.Path('/inputs')/name).read_bytes()).hexdigest() for name in names}
    result.update(status='passed',summary=summary,conversion_calls=len(conversions),
        all_cached_payload_facts_unchanged=True,
        declared_type_witness_count=sum(f.get('payload_kind')=='declared_type_surface' for f in actual.values()),
        output_sha256={path.name:hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted((root/'analysis').iterdir()) if path.is_file()})
except Exception as error:
    result.update(error=pipeline.error_fields(error,'publication'))
    raise
finally:
    result['publisher_seconds'] = time.monotonic()-started
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
'''


def command(image, inputs, program, volume, hashes, input_hashes, name):
    if not utilities.IMAGE_ID.fullmatch(image) or not volume.startswith('sbom-r113-publisher-'):
        raise ValueError('Pinned image and owned new native workspace are required')
    return ['docker', 'run', '--name', name, '--pull=never', '--no-healthcheck', '--network=none',
        '--read-only', '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--memory=3g', '--cpus=2', '--pids-limit=128',
        '--tmpfs=/tmp:rw,nosuid,nodev,size=512m,mode=1777',
        '--mount', f'type=bind,src={inputs},dst=/inputs,readonly',
        '--mount', f'type=bind,src={program},dst=/harness/program.py,readonly',
        '--mount', f'type=volume,src={volume},dst=/workspace',
        '--env', 'R113_PACKAGE_HASHES=' + json.dumps(hashes, sort_keys=True, separators=(',', ':')),
        '--env', 'R113_INPUT_HASHES=' + json.dumps(input_hashes, sort_keys=True, separators=(',', ':')),
        '--entrypoint=python', image, '/harness/program.py']


def ready_host():
    report, freeze = json.loads((HOST / 'report.json').read_bytes()), json.loads((HOST / 'freeze.json').read_bytes())
    if (report.get('status') != 'passed' or report.get('oracle_read') is not False
            or report.get('all_frozen_inputs_source_converter_unchanged') is not True
            or report.get('freeze_sha256') != utilities.sha(HOST / 'freeze.json')
            or [row['name'] for row in report.get('cases', [])] != ['chalk-original-r106', 'nest-types-r109']):
        raise ValueError('Both sealed current host publications must precede the installed job')
    for row in report['cases']:
        folder = HOST / row['name']
        if (row.get('status') != 'passed' or row.get('oracle_read') is not False
                or row != json.loads((folder / 'run.json').read_bytes())
                or utilities.sha(folder / 'run.json') != report.get('run_sha256', {}).get(row['name'])):
            raise ValueError('Sealed per-case host status differs')
        for filename, expected in row['output_sha256'].items():
            if Path(filename).name != filename or utilities.sha(folder / 'analysis' / filename) != expected:
                raise ValueError('Current host comparison outputs changed')
    return freeze


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root-runtime-ready', action='store_true')
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    if not args.root_runtime_ready:
        raise ValueError('Explicit committed runtime and both host jobs READY required')
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError('Preserve every installed job attempt; do not retry blindly')
    host_freeze = ready_host()
    source = ROOT / 'src/sbom_creator'
    hashes = {path.relative_to(source).as_posix(): utilities.sha(path) for path in sorted(source.rglob('*'))
              if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    if len(hashes) != 49 or {'sbom_creator/' + name: value for name, value in hashes.items()} != host_freeze['code_sha256']:
        raise ValueError('Installed source must equal the current 49-file host freeze')
    output.mkdir(parents=True)
    shutil.copyfile(__file__, output / 'executed-harness.py')
    program_path, inputs = output / 'container-program.py', output / 'cached-inputs'
    program_path.write_text(PROGRAM, encoding='utf-8', newline='\n')
    inputs.mkdir()
    for name in NAMES:
        shutil.copyfile(INPUTS / name, inputs / name)
    input_hashes = {name: utilities.sha(inputs / name) for name in NAMES}
    snapshot = output / 'executed-source/sbom_creator'
    shutil.copytree(source, snapshot, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    environment = utilities.host_environment()
    build_files = {name: utilities.sha(ROOT / name) for name in ('Dockerfile', '.dockerignore', 'pyproject.toml')}
    volume = 'sbom-r113-publisher-' + str(time.time_ns())
    freeze = {'reference_accessed': False, 'fresh_scans': False, 'fresh_physical_reads': False,
        'new_accuracy_measurement': False, 'source_sha256': hashes, 'build_file_sha256': build_files,
        'input_sha256': input_hashes, 'harness_sha256': utilities.sha(__file__),
        'container_program_sha256': utilities.sha(program_path),
        'helper_sha256': {name: utilities.sha(ROOT / 'benchmarks' / name)
                          for name in ('check_mvp_r111_cold_cache.py', 'check_mvp_r112_container.py')},
        'host_report_sha256': utilities.sha(HOST / 'report.json'), 'workspace_volume': volume,
        'frozen_at': datetime.now(UTC).isoformat(), 'host_environment_names': sorted(environment)}
    utilities.write(output / 'freeze.json', freeze)
    started = time.monotonic()
    build_command = ['docker', 'build', '--progress=plain', '--tag', 'sbom-creator:mvp-r113', '.']
    with (output / 'build.log').open('wb') as log:
        built = subprocess.run(build_command, cwd=ROOT, env=environment, stdout=log,
            stderr=subprocess.STDOUT, timeout=900, check=False)
    utilities.write(output / 'build.json', {'exit_code': built.returncode, 'seconds': time.monotonic() - started,
        'command': build_command})
    if built.returncode:
        return 2
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', 'sbom-creator:mvp-r113'], env=environment))[0]
    utilities.write(output / 'built-image.json', image)
    image_id = image['Id']
    if any(entry.split('=', 1)[0] in {'SBOM_JAVA_ARCHIVE_COMPONENTS', 'SBOM_JAVA_NESTED_WINDOWS'}
           for entry in image['Config'].get('Env', [])):
        raise ValueError('Feature overrides cannot impersonate release defaults')
    subprocess.run(['docker', 'volume', 'create', '--label', 'sbom-stage=r113-cached-publisher', volume],
                   env=environment, capture_output=True, check=True, timeout=30)
    name = 'sbom-r113-publisher-' + str(time.time_ns())
    args = command(image_id, inputs, program_path, volume, hashes, input_hashes, name)
    started = time.monotonic()
    with (output / 'container.log').open('wb') as log:
        try:
            code = subprocess.run(args, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=180, check=False).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'kill', name], env=environment, stdout=log,
                           stderr=subprocess.STDOUT, timeout=30, check=False)
            code = 124
    elapsed = time.monotonic() - started
    observed = inspect(name, environment)
    utilities.write(output / 'container-inspect.json', observed)
    copied = {}
    for filename in ('result.json', 'environment.json', 'analysis'):
        copied[filename] = utilities.copy_from(name, '/workspace/' + filename, output / filename, environment)
    subprocess.run(['docker', 'rm', name], env=environment, capture_output=True, timeout=30, check=False)
    exports = utilities.export_analysis(output)
    export_checks = utilities.verify_exports(output, exports)
    result = json.loads((output / 'result.json').read_bytes()) if copied['result.json'] else {}
    facts = json.loads((output / 'environment.json').read_bytes()) if copied['environment.json'] else {}
    parity = {}
    if copied['analysis']:
        for view in VIEWS:
            actual = json.loads((output / 'analysis' / (view + '.cdx.json')).read_bytes())
            expected = json.loads((HOST / 'nest-types-r109/analysis' / (view + '.cdx.json')).read_bytes())
            parity[view] = utilities.coordinates(actual) == utilities.coordinates(expected)
        actual = json.loads((output / 'analysis/selected.syft.json').read_bytes())
        expected = json.loads((HOST / 'nest-types-r109/analysis/selected.syft.json').read_bytes())
        parity['selected_ids'] = {row['id'] for row in actual['artifacts']} == {row['id'] for row in expected['artifacts']}
    command_exact = (observed['image_id'] == image_id and observed['path'] == 'python'
        and observed['args'] == ['/harness/program.py'] and observed['config']['Cmd'] == ['/harness/program.py']
        and facts.get('executed_program_sha256') == utilities.sha(program_path))
    unchanged = (all(utilities.sha(source / name) == value for name, value in hashes.items())
        and all(utilities.sha(ROOT / name) == value for name, value in build_files.items())
        and all(utilities.sha(inputs / name) == value for name, value in input_hashes.items()))
    report = {'status': 'passed' if code == 0 and result.get('status') == 'passed' and all(copied.values())
        and exports and all(export_checks.values()) and all(parity.values()) and command_exact and unchanged else 'failed',
        'exit_code': code, 'image_id': image_id, 'container_seconds': elapsed, 'result': result,
        'host_nest_coordinate_and_selected_id_parity': parity, 'actual_command_verified': command_exact,
        'export_success': copied, 'compressed_exports_verified': export_checks,
        'frozen_source_inputs_build_files_unchanged': unchanged, 'workspace_volume_retained': volume,
        'reference_accessed': False, 'new_accuracy_measurement': False, 'fresh_scans': False,
        'fresh_physical_reads': False, 'database_read_or_downloaded': False,
        'container_flags': args[1:args.index(image_id)]}
    utilities.write(output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'image_id': image_id, 'container_seconds': elapsed}))
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())

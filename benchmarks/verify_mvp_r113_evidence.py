"""Verify completed R113 publications and installed evidence without rerunning jobs."""
from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'benchmarks/results'
COMMIT = '7726706ae2e56c7f4c4a300142d24de5a356be75'
TARGET = RESULTS / 'mvp-r113-final-validation.json'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def main():
    if TARGET.exists():
        raise FileExistsError('Preserve completed validation')
    host = RESULTS / 'mvp-r113-publication-v1'
    container = RESULTS / 'mvp-r113-container-v1'
    native = RESULTS / 'mvp-r113-native-publication-v2'
    frozen = read(host / 'freeze.json')
    marker = read(host / 'report.json')
    assert sha(host / 'report.json') == 'd72f8041f23408745e86df26367f92fe784ecac4b602ab3d27674f2db3a366a3'
    assert marker['status'] == 'passed' and marker['conversion_calls'] == 2
    assert marker['freeze_sha256'] == sha(host / 'freeze.json')
    assert marker['historical_chalk_failure_preserved']
    for key in ('oracle_read', 'fresh_scanners', 'fresh_physical_reads', 'source_input',
                'project_execution', 'new_accuracy_measurement', 'historical_chalk_failure_fixed_claim'):
        assert marker[key] is False and frozen[key] is False
    exact, eol = [], []
    for name, digest in frozen['code_sha256'].items():
        actual = ROOT / 'src' / name
        assert sha(actual) == sha(host / 'executed-source' / name) == digest
        assert sha(native / 'executed-source' / name) == digest
        assert sha(container / 'executed-source' / name) == digest
        committed = subprocess.run(['git', 'show', COMMIT + ':src/' + name],
            cwd=ROOT, capture_output=True, check=True).stdout
        raw = actual.read_bytes()
        if committed == raw:
            exact.append(name)
        else:
            assert committed.replace(b'\r\n', b'\n') == raw.replace(b'\r\n', b'\n')
            eol.append(name)
    assert len(exact) + len(eol) == 49
    previous = read(RESULTS / 'mvp-r112-java-v1/freeze.json')['code_sha256']
    changed = sorted(name for name, digest in previous.items() if frozen['code_sha256'][name] != digest)
    added = sorted(set(frozen['code_sha256']) - set(previous))
    assert changed == ['sbom_creator/cli.py', 'sbom_creator/pipeline.py', 'sbom_creator/service.py']
    assert added == ['sbom_creator/publication.py']
    for name, digest in frozen['input_sha256'].items():
        assert sha(ROOT / name) == digest
    assert sha(ROOT / '.tools/syft/syft.exe') == frozen['syft_converter_sha256']
    for case in marker['cases']:
        directory = host / case['name']
        assert sha(directory / 'run.json') == marker['run_sha256'][case['name']]
        assert read(directory / 'run.json') == case
        assert case['selected_artifact_ids_equal'] and case['all_original_payload_facts_equal']
        assert all(view['coordinate_multiset_equal'] and view['schema_valid'] for view in case['views'].values())
        for name, digest in case['output_sha256'].items():
            assert Path(name).name == name and sha(directory / 'analysis' / name) == digest

    native_report = read(native / 'report.json')
    assert native_report['status'] == 'passed' and native_report['skips'] == 0
    assert len(native_report['cases']) == 5
    assert native_report['source_sha256'] == frozen['code_sha256']
    installed_freeze = read(container / 'freeze.json')
    installed = read(container / 'report.json')
    environment = read(container / 'environment.json')
    local_hashes = {name.removeprefix('sbom_creator/'): digest for name, digest in frozen['code_sha256'].items()}
    assert installed_freeze['source_sha256'] == environment['installed_source_hashes'] == local_hashes
    assert installed_freeze['host_report_sha256'] == sha(host / 'report.json')
    assert installed['status'] == 'passed' and installed['exit_code'] == 0
    assert installed['actual_command_verified'] and installed['frozen_source_inputs_build_files_unchanged']
    assert all(installed['host_nest_coordinate_and_selected_id_parity'].values())
    assert all(installed['compressed_exports_verified'].values()) and len(installed['compressed_exports_verified']) == 13
    assert environment['java_archive_components_default'] is True
    assert environment['java_nested_windows_default'] is False and environment['feature_overrides_absent']
    for key in ('fresh_scans', 'fresh_physical_reads', 'reference_accessed', 'database_read_or_downloaded'):
        assert installed[key] is False and environment[key] is False
    assert installed['new_accuracy_measurement'] is False
    assert environment['uid'] == 10001 and environment['root_read_only'] and not environment['docker_socket_present']
    assert sha(container / 'container-program.py') == installed_freeze['container_program_sha256'] == environment['executed_program_sha256']
    inspect = read(container / 'container-inspect.json')
    assert inspect['path'] == 'python' and inspect['args'] == inspect['config']['Cmd'] == ['/harness/program.py']
    assert inspect['image_id'] == installed['image_id']
    for name, digest in installed_freeze['input_sha256'].items():
        assert sha(container / 'cached-inputs' / name) == digest
    for name, record in read(container / 'artifact-manifest.json').items():
        packed = container / record['file']
        assert sha(packed) == record['stored_sha256'] and packed.stat().st_size == record['stored_bytes']
        with gzip.open(packed, 'rb') as stream:
            raw = stream.read(record['original_bytes'] + 1)
        assert len(raw) == record['original_bytes']
        assert hashlib.sha256(raw).hexdigest() == record['original_sha256']
        assert sha(container / 'analysis' / name) == record['original_sha256']

    prior = read(RESULTS / 'mvp-r112-final-validation.json')['old_manifests_sha256']
    prior['mvp-r112-evidence-manifest.json'] = '16fa49694e51a85974aaeeaceb98a7438c7a8e45b830a5758277f9cc20791ad1'
    assert all(sha(RESULTS / name) == digest for name, digest in prior.items())
    reports, passed, skipped = {}, set(), set()
    for name in ('mvp-r113-full-service-v1.xml', 'mvp-r113-benchmark-tests-v1.xml',
                 'mvp-r113-container-tests-v1.xml'):
        document = ET.parse(RESULTS / name)
        suite = next(document.iter('testsuite')).attrib
        assert int(suite['errors']) == int(suite['failures']) == 0
        reports[name] = {**suite, 'sha256': sha(RESULTS / name)}
        for case in document.iter('testcase'):
            node = (case.attrib['classname'], case.attrib['name'])
            (skipped if case.find('skipped') is not None else passed).add(node)
    assert len(passed) == 971 and len(skipped) == 10 and not passed.intersection(skipped)
    report = {'status': 'PASS', 'runtime_commit': COMMIT, 'source_files': 49,
        'git_byte_exact': exact, 'git_crlf_lf_only': eol, 'changed_existing_source_since_r112': changed,
        'added_source_since_r112': added, 'component_classifier_files_unchanged_since_r112': True,
        'executed_snapshots_unchanged': True, 'old_manifests_sha256': prior,
        'host_publication_report_sha256': sha(host / 'report.json'),
        'installed_report_sha256': sha(container / 'report.json'), 'installed_image_id': installed['image_id'],
        'installed_export_count': 13, 'native_linux_contracts': 5, 'native_linux_skips': 0,
        'test_reports': reports, 'unique_passing_test_nodes': len(passed), 'unique_skipped_test_nodes': len(skipped),
        'new_accuracy_measurement': False, 'historical_chalk_failure_cause': 'UNKNOWN',
        'historical_chalk_failure_fixed_claim': False, 'deployed_services_changed': False,
        'foreign_recipes_or_reference_pairs_rebuilt': False}
    TARGET.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'PASS', 'byte_exact': len(exact), 'eol_only': len(eol),
        'passing_tests': len(passed), 'skipped_tests': len(skipped)}))


if __name__ == '__main__':
    main()

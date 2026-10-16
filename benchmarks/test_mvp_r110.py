import copy
import json
from pathlib import Path
from types import SimpleNamespace

import evaluate_mvp_r110 as evaluator
import pytest
import run_mvp_r110 as runner


def terminal():
    freeze = {'oracle_read': False, 'source_input': False, 'project_execution': False,
        'fresh_scanners': True, 'fresh_physical_reads': True,
        'java_archive_components_default': True, 'java_archive_components_override_supplied': False,
        'cases': ['rest', 'dbcp'], 'fresh_blind_independent_claim': False}
    marker = {'oracle_read': False, 'cases': ['rest', 'dbcp'], 'completed': ['rest', 'dbcp'],
        'failed': [], 'freeze_sha256': 'a' * 64,
        'all_predictions_terminal_before_reference_access': True}
    return marker, freeze


def test_both_terminal_cases_and_default_mode_required():
    marker, freeze = terminal()
    evaluator.validate_completion(marker, freeze, 'a' * 64)
    marker['completed'], marker['failed'] = ['rest'], ['dbcp']
    evaluator.validate_completion(marker, freeze, 'a' * 64)


@pytest.mark.parametrize('field,value', [
    ('cases', ['rest']), ('cases', ['rest', 'rest']), ('completed', ['rest']),
    ('failed', ['dbcp']), ('oracle_read', True), ('freeze_sha256', 'b' * 64),
    ('all_predictions_terminal_before_reference_access', False),
])
def test_no_partial_or_resealed_marker_allows_oracle(field, value):
    marker, freeze = terminal()
    marker[field] = value
    with pytest.raises(ValueError):
        evaluator.validate_completion(marker, freeze, 'a' * 64)


@pytest.mark.parametrize('field,value', [
    ('oracle_read', True), ('source_input', True), ('fresh_scanners', False),
    ('fresh_physical_reads', False), ('java_archive_components_default', False),
    ('java_archive_components_override_supplied', True), ('fresh_blind_independent_claim', True),
])
def test_wrong_execution_mode_cannot_be_default_held_control(field, value):
    marker, freeze = terminal()
    freeze[field] = value
    with pytest.raises(ValueError):
        evaluator.validate_completion(marker, freeze, 'a' * 64)


@pytest.mark.parametrize('path', ['../secret', 'C:/oracle', r'windows\path',
                                  '/absolute', 'benchmarks/references/paired-x/sbom.json'])
def test_prediction_input_cannot_point_to_oracle_or_escape(path):
    with pytest.raises(ValueError):
        runner.safe_relative(path)


def test_false_runtime_default_cannot_be_hidden_by_runner():
    with pytest.raises(ValueError):
        runner.require_release_defaults(SimpleNamespace(java_archive_components=False, java_image_evidence=True))
    runner.require_release_defaults(SimpleNamespace(java_archive_components=True, java_image_evidence=True))


def test_input_cases_use_only_observed_image_metadata(tmp_path):
    for pair in runner.CASES.values():
        folder = tmp_path / 'benchmarks/.work' / pair
        (folder / 'analysis').mkdir(parents=True)
        (folder / 'image.tar').write_bytes(b'existing-image')
        (folder / 'analysis/image.syft.json').write_text(json.dumps({
            'descriptor': {'name': 'syft', 'version': '1.51.1'},
            'source': {'type': 'image', 'metadata': {'imageID': 'sha256:' + '1' * 64,
                                                    'manifestDigest': 'sha256:' + '2' * 64}},
            'artifacts': [{'purl': 'not-used-to-select-inputs'}]}))
    rows = runner.input_cases(tmp_path)
    assert [row['name'] for row in rows] == ['rest', 'dbcp']
    assert all(row['image'].endswith('@sha256:' + '2' * 64) for row in rows)
    path = tmp_path / 'benchmarks/.work/paired-commons-dbcp-v1/analysis/image.syft.json'
    document = json.loads(path.read_bytes())
    document['source']['type'] = 'directory'
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='image producer'):
        runner.input_cases(tmp_path)


def test_failed_preflight_never_opens_reference_evaluator(tmp_path, monkeypatch):
    entered = []
    def refused(_output):
        raise ValueError('both predictions missing')
    monkeypatch.setattr(evaluator, 'prepare', refused)
    monkeypatch.setattr(evaluator, 'evaluate_case', lambda *_args: entered.append(True))
    monkeypatch.setattr('sys.argv', ['evaluate_mvp_r110', '--output', str(tmp_path)])
    with pytest.raises(ValueError, match='predictions missing'):
        evaluator.main()
    assert not entered


def test_unknown_prediction_is_fn_not_empty_success():
    result = evaluator.component_metrics(set(), {'pkg:maven/example/lib@1'})
    assert result['components']['tp'] == 0 and result['components']['fn'] == 1
    assert result['components']['recall'] == 0 and result['components']['precision'] is None
    assert result['versions']['exact_version_coverage'] == 0


def test_marker_validation_does_not_mutate_evidence():
    marker, freeze = terminal()
    original = copy.deepcopy((marker, freeze))
    evaluator.validate_completion(marker, freeze, 'a' * 64)
    assert (marker, freeze) == original


def test_source_binding_distinguishes_mandatory_files_and_ancillary_bytecode():
    sources = {f'sbom_creator/mod{i}.py': 'a' * 64 for i in range(47)}
    code = {**sources, 'sbom_creator/__pycache__/mod0.cpython-311.pyc': 'b' * 64}
    actual_sources, caches = evaluator.frozen_source_sets(code)
    assert actual_sources == sources and len(caches) == 1
    with pytest.raises(ValueError, match='mandatory'):
        evaluator.frozen_source_sets({'sbom_creator/__pycache__/mod0.pyc': 'b' * 64})
    with pytest.raises(ValueError, match='cache artifact'):
        evaluator.frozen_source_sets({**sources, 'sbom_creator/stray.pyc': 'c' * 64})


def test_lossless_bytecode_evidence_allows_missing_cache_but_never_missing_source(tmp_path):
    snapshot = tmp_path / 'executed-source'
    (snapshot / 'sbom_creator/__pycache__').mkdir(parents=True)
    code = {}
    for i in range(47):
        relative = f'sbom_creator/mod{i}.py'
        (snapshot / relative).write_text(f'# source {i}\n')
        code[relative] = runner.sha(snapshot / relative)
    cache = Path('sbom_creator/__pycache__/mod0.cpython-311.pyc')
    # Deliberately inert bytes: the evaluator preserves, hashes and never loads.
    (snapshot / cache).write_bytes(b'never execute archived bytecode')
    code[cache.as_posix()] = runner.sha(snapshot / cache)
    freeze = {'code_sha256': code}
    (tmp_path / 'freeze.json').write_text(json.dumps(freeze))
    result = evaluator.portable_source_binding(tmp_path, freeze)
    assert result['mandatory_source_schema_count'] == 47 and result['ancillary_generated_cache_count'] == 1
    (snapshot / cache).unlink()
    assert evaluator.portable_source_binding(tmp_path, freeze) == result
    (snapshot / 'sbom_creator/mod0.py').unlink()
    with pytest.raises(FileNotFoundError):
        evaluator.portable_source_binding(tmp_path, freeze)

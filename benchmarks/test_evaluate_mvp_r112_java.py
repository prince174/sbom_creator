"""Synthetic, no-oracle tests for six-case completion and partial-scope metrics."""
import copy
import json

import evaluate_mvp_r112_java as evaluator
import pytest


def terminal():
    freeze = {'oracle_read': False, 'source_input': False, 'project_execution': False,
        'reference_build_cache_read': False, 'fresh_syft_image_scans': False,
        'fresh_trivy_image_scans': True, 'fresh_physical_reads': True,
        'actual_service_publisher': True, 'fresh_blind_independent_claim': False,
        'java_archive_components_default': True, 'java_archive_components_override_supplied': False,
        'java_nested_windows_default': False, 'network_downloads_permitted': False,
        'build_or_registry_acquisition_permitted': False, 'cases': list(evaluator.CASES)}
    marker = {'oracle_read': False, 'cases': list(evaluator.CASES),
        'completed': list(evaluator.CASES), 'failed': [], 'freeze_sha256': 'a' * 64,
        'all_predictions_terminal_before_reference_access': True,
        'all_frozen_source_tool_database_image_catalog_inputs_unchanged': True}
    return marker, freeze


def test_six_terminal_statuses_and_immutable_mode_do_not_mutate_evidence():
    marker, freeze = terminal()
    original = copy.deepcopy((marker, freeze))
    evaluator.completion_valid(marker, freeze, 'a' * 64)
    assert (marker, freeze) == original
    marker['failed'], marker['completed'] = ['dbcp'], list(evaluator.CASES)[:-1]
    evaluator.completion_valid(marker, freeze, 'a' * 64)


@pytest.mark.parametrize('field,value', [
    ('cases', list(reversed(evaluator.CASES))), ('completed', ['boot']),
    ('failed', ['dbcp']), ('completed', list(evaluator.CASES) + ['boot']),
    ('oracle_read', True), ('freeze_sha256', 'b' * 64),
    ('all_predictions_terminal_before_reference_access', False),
    ('all_frozen_source_tool_database_image_catalog_inputs_unchanged', False),
])
def test_partial_duplicate_reordered_or_unsealed_marker_rejected(field, value):
    marker, freeze = terminal()
    marker[field] = value
    with pytest.raises(ValueError):
        evaluator.completion_valid(marker, freeze, 'a' * 64)


@pytest.mark.parametrize('field', [
    'oracle_read', 'source_input', 'project_execution', 'reference_build_cache_read',
    'fresh_syft_image_scans', 'fresh_trivy_image_scans', 'fresh_physical_reads',
    'actual_service_publisher', 'fresh_blind_independent_claim',
    'java_archive_components_default', 'java_archive_components_override_supplied',
    'java_nested_windows_default', 'network_downloads_permitted',
    'build_or_registry_acquisition_permitted',
])
def test_each_execution_mode_flag_is_required_as_boolean(field):
    marker, freeze = terminal()
    freeze[field] = not freeze[field]
    with pytest.raises(ValueError, match='execution mode'):
        evaluator.completion_valid(marker, freeze, 'a' * 64)


def source_fixture(output):
    folder = output / 'executed-source' / 'sbom_creator'
    folder.mkdir(parents=True)
    result = {}
    for index in range(48):
        path = folder / f'mod{index}.py'
        path.write_text(f'# {index}\n')
        result['sbom_creator/' + path.name] = evaluator.sha(path)
    return result


def test_all_48_actual_source_files_required_generated_caches_are_not_sources(tmp_path):
    source = source_fixture(tmp_path)
    evaluator.source_valid(tmp_path, source)
    cache = tmp_path / 'executed-source/sbom_creator/__pycache__/mod0.pyc'
    cache.parent.mkdir()
    cache.write_bytes(b'ancillary generated cache is never executed by evaluator')
    evaluator.source_valid(tmp_path, source)
    poisoned = {**source, 'sbom_creator/__pycache__/mod0.pyc': evaluator.sha(cache)}
    with pytest.raises(ValueError, match='48'):
        evaluator.source_valid(tmp_path, poisoned)
    first = tmp_path / 'executed-source/sbom_creator/mod0.py'
    first.write_text('# changed\n')
    with pytest.raises(ValueError, match='changed'):
        evaluator.source_valid(tmp_path, source)


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'cache-in-freeze'])
def test_missing_unsealed_or_frozen_cache_never_satisfies_source_seal(tmp_path, mutation):
    source = source_fixture(tmp_path)
    folder = tmp_path / 'executed-source/sbom_creator'
    if mutation == 'missing':
        (folder / 'mod0.py').unlink()
    elif mutation == 'extra':
        (folder / 'unsealed.py').write_text('# extra\n')
    else:
        del source['sbom_creator/mod0.py']
        source['sbom_creator/stray.pyc'] = 'a' * 64
    with pytest.raises(ValueError):
        evaluator.source_valid(tmp_path, source)


def test_missing_root_authorization_never_calls_preflight_or_oracle(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(evaluator, 'preflight', lambda *_args: calls.append('preflight'))
    monkeypatch.setattr(evaluator, 'evaluate_all', lambda *_args: calls.append('oracle'))
    monkeypatch.setattr('sys.argv', ['evaluator', '--output', str(tmp_path / 'not-created')])
    with pytest.raises(ValueError, match='ALL6READY'):
        evaluator.main()
    assert not calls and not (tmp_path / 'not-created').exists()


def test_failed_prediction_preflight_never_opens_reference(tmp_path, monkeypatch):
    calls = []
    def reject(_output):
        raise ValueError('Prediction seals incomplete')
    monkeypatch.setattr(evaluator, 'preflight', reject)
    monkeypatch.setattr(evaluator, 'evaluate_all', lambda *_args: calls.append('oracle'))
    monkeypatch.setattr('sys.argv', ['evaluator', '--root-all-six-ready',
                                  '--output', str(tmp_path / 'not-created')])
    with pytest.raises(ValueError, match='seals incomplete'):
        evaluator.main()
    assert not calls and not (tmp_path / 'not-created').exists()


def test_all_ecosystem_inventory_multiset_retains_os_and_duplicates():
    component = {'type': 'library', 'name': 'libc', 'version': '1', 'purl': 'pkg:deb/debian/libc@1'}
    one = {'components': [component]}
    two = {'components': [component, component]}
    assert sum(evaluator.multiset(one).values()) == 1
    assert sum((evaluator.multiset(two) - evaluator.multiset(one)).values()) == 1
    wrong_version = {'components': [{**component, 'version': '2', 'purl': 'pkg:deb/debian/libc@2'}]}
    assert evaluator.multiset(one) != evaluator.multiset(wrong_version)


def test_unknown_prediction_is_fn_and_never_empty_precision_success():
    row = evaluator.metrics_row(set(), {'pkg:maven/example/lib@1'})
    assert row['components']['tp'] == 0 and row['components']['fn'] == 1
    assert row['components']['precision'] is None and row['components']['recall'] == 0
    assert row['versions']['version_accuracy_matched_identity'] is None
    assert row['versions']['exact_version_coverage_known_delivered'] == 0


def test_equal_counts_and_conditional_version_accuracy_do_not_hide_wrong_identity_or_version():
    expected = {'pkg:maven/example/lib@1', 'pkg:maven/example/other@1'}
    row = evaluator.metrics_row({'pkg:maven/example/lib@2', 'pkg:maven/example/unrelated@1'}, expected)
    assert row['count_delta'] == 0
    assert (row['components']['tp'], row['components']['fp'], row['components']['fn']) == (0, 2, 2)
    assert row['versions']['matched_identity_count'] == 1
    assert row['versions']['version_accuracy_matched_identity'] == 0
    correct_only = evaluator.metrics_row({'pkg:maven/example/lib@1'}, expected)
    assert correct_only['versions']['version_accuracy_matched_identity'] == 1
    assert correct_only['versions']['exact_version_coverage_known_delivered'] == .5


def test_version_denominator_retains_expected_multiple_version_instances():
    row = evaluator.metrics_row({'pkg:maven/example/lib@1'},
                               {'pkg:maven/example/lib@1', 'pkg:maven/example/lib@2'})
    assert row['versions']['matched_identity_count'] == 2
    assert row['versions']['version_accuracy_matched_identity'] == .5


def test_version_aggregate_weights_instances_and_retains_undefined_empty():
    rows = [{'exact_version_tp': 90, 'matched_identity_count': 90, 'expected_count': 100},
            {'exact_version_tp': 0, 'matched_identity_count': 1, 'expected_count': 1}]
    result = evaluator.versions_aggregate(rows)
    assert result['version_accuracy_matched_identity'] == 90 / 91
    assert result['exact_version_coverage_known_delivered'] == 90 / 101
    assert evaluator.versions_aggregate([])['version_accuracy_matched_identity'] is None


def summary_report(actual, expected, *, scope_unknown=0, packaging_unknown=0):
    row = evaluator.metrics_row(actual, expected)
    owner = {'path': 'owner', 'owner': 'pkg:maven/example/app@1',
        'known_delivered_coordinate_count': len(expected),
        'known_delivered_conservative': row['components'], 'versions': row['versions']}
    version = evaluator.versions_aggregate([{**row['versions'], 'expected_count': len(expected)}])
    known = {'rows': [owner], 'known_delivered_conservative_micro': row['components'],
        'versions': version, 'partial_reference_scope_owners': 1,
        'unknown_packaging_observations': packaging_unknown,
        'empty_known_reference_owners': int(not expected), 'count_delta_known_reference': row['count_delta']}
    return {'known_delivered_views': {'final': known},
        'historical_conservative_scope': {'components': row['components'],
            'scope_unknown_owners': scope_unknown, 'versions_scored_scope': version,
            'direct': evaluator.metrics_row(set(), {'pkg:maven/example/direct@1'})['components']}}


def test_high_micro_cannot_hide_failed_repository_weak_owner_or_unknown_scopes():
    expected = {f'pkg:maven/example/lib{i}@1' for i in range(100)}
    reports = {'large': summary_report(expected, expected, scope_unknown=31, packaging_unknown=8),
               'failed': summary_report(set(), {'pkg:maven/example/missing@1'})}
    result = evaluator.summarize(reports)
    assert result['same_known_delivered_final_micro']['recall'] > .99
    assert result['same_known_delivered_repository_macro']['recall'] == .5
    assert result['weak_known_delivered_repositories'] == ['failed']
    assert result['weak_known_delivered_owners'][0]['case'] == 'failed'
    assert result['historical_unknown_scope_owners'] == 31
    assert result['unknown_packaging_observations'] == 8
    assert result['image_only_direct_unknown']['fn'] == 2
    assert result['every_disclosed_repository_known_delivered_p_r_versions_over_90'] is False
    assert result['acceptance'] is False


def test_empty_roots_are_undefined_not_successful_thresholds():
    result = evaluator.summarize({'empty': summary_report(set(), set())})
    assert result['empty_known_reference_owner_count'] == 1
    assert result['same_known_delivered_final_micro']['precision'] is None
    assert result['same_known_delivered_positive_owner_macro']['recall'] is None
    assert result['weak_known_delivered_repositories'] == ['empty']


def test_baseline_manifest_seals_every_compared_view_and_selected_ids(tmp_path, monkeypatch):
    for case in evaluator.CASES:
        folder = tmp_path / case
        folder.mkdir()
        for filename in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json', 'selected.syft.json', 'image-peer.cdx.json'):
            (folder / filename).write_text(json.dumps({'case': case, 'file': filename}))
    monkeypatch.setattr(evaluator, 'baseline', lambda case: tmp_path / case)
    manifest = evaluator.baseline_hashes()
    assert set(manifest) == set(evaluator.CASES)
    assert all(set(row) == {'final.cdx.json', 'os.cdx.json', 'full.cdx.json',
                           'selected.syft.json', 'image-peer.cdx.json'}
               for row in manifest.values())
    original = manifest['boot']['os.cdx.json']
    (tmp_path / 'boot/os.cdx.json').write_text('{}')
    assert evaluator.baseline_hashes()['boot']['os.cdx.json'] != original


def peer_document():
    return {'metadata': {'component': {'properties': [
        {'name': 'aquasecurity:trivy:ImageID', 'value': 'sha256:' + 'a' * 64}]}},
        'components': [{'type': 'library', 'group': 'example', 'name': 'lib', 'version': '1',
            'purl': 'pkg:maven/example/lib@1', 'bom-ref': 'random-before', 'properties': [
                {'name': 'aquasecurity:trivy:FilePath', 'value': 'app/lib.jar'},
                {'name': 'aquasecurity:trivy:LayerDiffID', 'value': 'sha256:' + 'b' * 64}]}]}


@pytest.mark.parametrize('field', ['bom-ref', 'path', 'layer'])
def test_raw_peer_comparison_ignores_random_ids_but_not_same_coordinate_wrong_path_or_layer(
        tmp_path, monkeypatch, field):
    monkeypatch.setattr(evaluator, 'ROOT', tmp_path)
    previous, current = peer_document(), peer_document()
    if field == 'bom-ref':
        current['components'][0]['bom-ref'] = 'random-after'
    else:
        property_name = 'aquasecurity:trivy:FilePath' if field == 'path' else 'aquasecurity:trivy:LayerDiffID'
        for row in current['components'][0]['properties']:
            if row['name'] == property_name:
                row['value'] = 'different'
    old, actual = tmp_path / 'old', tmp_path / 'actual'
    old.mkdir()
    actual.mkdir()
    (old / 'image-peer.cdx.json').write_text(json.dumps(previous))
    (actual / 'image-peer.cdx.json').write_text(json.dumps(current))
    result = evaluator.raw_peer_regression({'analysis': actual}, old)
    assert result['image_config_equal'] is True
    assert result['prior_component_instances'] == result['current_component_instances'] == 1
    assert result['raw_component_instances_equal'] is (field == 'bom-ref')
    assert result['added_instances'] == result['removed_instances'] == (0 if field == 'bom-ref' else 1)


def test_failed_prediction_peer_comparison_retains_every_removed_instance(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluator, 'ROOT', tmp_path)
    old = tmp_path / 'old'
    old.mkdir()
    (old / 'image-peer.cdx.json').write_text(json.dumps(peer_document()))
    result = evaluator.raw_peer_regression({'analysis': None}, old)
    assert result['current_component_instances'] == 0 and result['removed_instances'] == 1
    assert result['current_image_config'] is None and result['image_config_equal'] is False

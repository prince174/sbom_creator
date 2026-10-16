"""Regression tests for partial-reference metrics and independently bound root scope."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'benchmarks'))
from evaluate_reactor_packaged_r109 import (
    projected_components,
    score_module,
    score_repository,
    validate_module,
)

OWNER = 'pkg:maven/example/app@1'
LIB = 'pkg:maven/example/library@2'
EXTRA = 'pkg:maven/example/packaging-extra@1'
PREFIX = '/application/app/'
PRIMARY = PREFIX + 'app-1.jar'


def component(identity, path, virtual=None):
    return {'purl': identity, 'bom-ref': identity + path,
            'properties': [{'name': 'syft:location:0:path', 'value': path},
                           {'name': 'syft:metadata:virtualPath', 'value': virtual or path}]}


def module():
    return {'path': 'app', 'owner': OWNER, 'image_prefix': PREFIX,
            'known_file_labels': [{'image_path': PREFIX + 'library.jar',
                                   'coordinate': LIB, 'sha256': 'a' * 64}],
            'nested_file_labels': [], 'known_delivered_coordinate_set': [LIB],
            'primary_outputs': [{'image_path': PRIMARY, 'sha256': 'b' * 64,
                                 'status': 'VERIFIED_EFFECTIVE_PRIMARY_SHA256', 'owner': OWNER}],
            'unknown_standalone_files': [], 'unknown_nested_files': [],
            'unknown_shaded_content': [{'path': PRIMARY, 'reason': 'opaque primary code'}],
            'artifact_scope_complete': True, 'complete_image_component_scope_attested': False}


def recipe_primary_module():
    label = module()
    label['primary_outputs'][0].update(status='VERIFIED_RECIPE_EFFECTIVE_PRIMARY_SHA256', proof={
        'method': 'immutable_literal_recipe_effective_native_cdx_canonical_properties_full_sha256',
        'owner': OWNER, 'actual_physical_sha256': 'b' * 64, 'image_path': PRIMARY,
        'literal_copy_source': 'app/target/app-1.jar', 'literal_copy_destination': PREFIX,
        'effective_final_name': 'app-1', 'effective_build_directory': '/src/app/target',
        'dockerfile_sha256': 'c' * 64, 'effective_pom_sha256': 'd' * 64,
        'embedded_properties_path': 'META-INF/maven/example/app/pom.properties',
        'embedded_properties_sha256': 'e' * 64,
        'image_config_digest': 'sha256:' + 'f' * 64,
        'image_diff_id': 'sha256:' + 'a' * 64,
        'native_and_cdx_owner_agree': True, 'dependency_copy_collision_absent': True})
    return label


def test_all_projected_predictions_retained_unknown_packaging_extra_is_conservative_fp():
    document = {'components': [component(LIB, PREFIX + 'library.jar'),
                                component(EXTRA, PRIMARY, PRIMARY + ':BOOT-INF/lib/extra.jar')]}
    row = score_module(document, module())
    assert row['known_delivered_conservative'] == {
        'tp': 1, 'fp': 1, 'fn': 0, 'predicted': 2, 'reference': 1,
        'precision': .5, 'recall': 1, 'f1': 2 / 3}
    assert row['extra_conservatively_charged_fp'] == [EXTRA]
    assert row['status'] == 'PARTIAL_REFERENCE_SCOPE'
    assert 'global image recall UNKNOWN' in row['recall_interpretation']
    assert row['acceptance'] is False


def test_only_independently_attested_exact_root_excluded_nested_same_purl_retained():
    document = {'components': [component(OWNER, PRIMARY),
                                component(OWNER, PRIMARY, PRIMARY + ':lib/repeated-own-jar.jar'),
                                component(LIB, PREFIX + 'library.jar')]}
    actual, observations, exclusions = projected_components(document, module())
    assert actual == {OWNER, LIB}
    assert len(exclusions) == 1
    assert len(observations) == 2


def test_root_without_unambiguous_virtual_archive_path_remains_conservative_extra():
    candidate = component(OWNER, PRIMARY)
    candidate['properties'] = candidate['properties'][:1]
    actual, _, exclusions = projected_components({'components': [candidate]}, module())
    assert actual == {OWNER}
    assert exclusions == []


def test_root_coordinate_shared_by_two_physical_locations_not_silently_removed():
    candidate = component(OWNER, PRIMARY)
    candidate['properties'].append({'name': 'syft:location:1:path', 'value': PREFIX + 'copy.jar'})
    actual, _, exclusions = projected_components({'components': [candidate]}, module())
    assert actual == {OWNER}
    assert exclusions == []


def test_post_only_literal_recipe_effective_metadata_primary_proof_can_exclude_root():
    label = recipe_primary_module()
    report = {'modules': [label], 'actual_oci_binding': {'config_digest': 'sha256:' + 'f' * 64},
              'actual_image_diff_id': 'sha256:' + 'a' * 64}
    result = score_repository({'components': [component(OWNER, PRIMARY),
                                             component(LIB, PREFIX + 'library.jar')]}, report)
    assert result['known_delivered_conservative_micro']['tp'] == 1
    assert result['known_delivered_conservative_micro']['fp'] == 0
    assert result['unattested_primary_candidates'] == 0
    assert len(result['rows'][0]['independently_attested_root_exclusions']) == 1


@pytest.mark.parametrize('field', ['method', 'owner', 'actual_physical_sha256', 'image_path',
                                  'literal_copy_source', 'literal_copy_destination',
                                  'effective_final_name', 'embedded_properties_path',
                                  'native_and_cdx_owner_agree', 'dependency_copy_collision_absent'])
def test_recipe_primary_status_alone_or_incomplete_proof_never_excludes_root(field):
    label = recipe_primary_module()
    label['primary_outputs'][0]['proof'][field] = None
    actual, _, exclusions = projected_components({'components': [component(OWNER, PRIMARY)]}, label)
    assert actual == {OWNER}
    assert exclusions == []


@pytest.mark.parametrize('binding', ['image_config_digest', 'image_diff_id'])
def test_recipe_primary_proof_bound_to_different_image_is_not_accepted(binding):
    label = recipe_primary_module()
    label['primary_outputs'][0]['proof'][binding] = 'sha256:' + '9' * 64
    report = {'modules': [label], 'actual_oci_binding': {'config_digest': 'sha256:' + 'f' * 64},
              'actual_image_diff_id': 'sha256:' + 'a' * 64}
    with pytest.raises(ValueError, match='another image'):
        score_repository({'components': []}, report)


@pytest.mark.parametrize('change', ['status', 'owner', 'sha256', 'image_path'])
def test_unattested_primary_root_is_not_dropped_by_owner_name(change):
    label = module()
    label['primary_outputs'][0][change] = 'unproven'
    actual, _, exclusions = projected_components({'components': [component(OWNER, PRIMARY)]}, label)
    assert actual == {OWNER}
    assert exclusions == []


def test_wrong_version_is_fp_and_fn_despite_matching_component_count():
    row = score_module({'components': [component('pkg:maven/example/library@3', PREFIX + 'library.jar')]}, module())
    assert row['known_delivered_conservative']['tp'] == 0
    assert row['known_delivered_conservative']['fp'] == 1
    assert row['known_delivered_conservative']['fn'] == 1
    assert row['count_delta_known_reference'] == 0
    assert row['versions']['version_accuracy_matched_identity'] == 0
    assert row['versions']['exact_version_coverage_known_delivered'] == 0


def test_missing_or_unconfirmed_known_component_is_fn_not_scope_unknown_exclusion():
    row = score_module({'components': []}, module())
    assert row['known_delivered_conservative']['fn'] == 1
    assert row['known_delivered_conservative']['precision'] is None
    assert row['known_delivered_conservative']['recall'] == 0


def test_empty_truth_not_positive_macro_success():
    label = module()
    label.update(known_file_labels=[], known_delivered_coordinate_set=[])
    report = score_repository({'components': []}, {'modules': [label]})
    assert report['positive_known_reference_owners'] == 0
    assert report['empty_known_reference_owners'] == 1
    assert report['known_delivered_macro_positive_owners']['recall'] is None
    assert report['known_delivered_conservative_micro']['f1'] is None


def test_truth_cannot_drop_unmatched_delivered_reference_row():
    label = module()
    label['known_delivered_coordinate_set'] = []
    with pytest.raises(ValueError, match='every independently labelled'):
        validate_module(label)


def test_unverified_nested_member_crc_is_not_accepted_as_truth():
    label = module()
    label['nested_file_labels'] = [{'outer_image_path': PRIMARY, 'sha256': 'c' * 64,
                                    'coordinate': EXTRA, 'entry_crc_verified': False}]
    label['known_delivered_coordinate_set'].append(EXTRA)
    with pytest.raises(ValueError, match='complete member CRC'):
        validate_module(label)


def test_incomplete_shading_or_root_cannot_claim_complete_image_scope():
    label = module()
    label['complete_image_component_scope_attested'] = True
    with pytest.raises(ValueError, match='Incomplete packaging evidence'):
        validate_module(label)
    label['unknown_shaded_content'] = []
    label['primary_outputs'][0]['status'] = 'UNKNOWN_PRIMARY_CANDIDATE'
    with pytest.raises(ValueError, match='Incomplete packaging evidence'):
        validate_module(label)


def test_duplicate_or_overlapping_owner_prefixes_rejected():
    label = module()
    other = copy.deepcopy(label)
    with pytest.raises(ValueError, match='non-overlapping'):
        score_repository({'components': []}, {'modules': [label, other]})
    other['image_prefix'] = PREFIX + 'child/'
    with pytest.raises(ValueError, match='non-overlapping'):
        score_repository({'components': []}, {'modules': [label, other]})


def test_outside_owner_and_non_maven_platform_do_not_pollute_project_view():
    document = {'components': [component(LIB, PREFIX + 'library.jar'),
                                component('pkg:npm/npm@10', PREFIX + 'npm'),
                                component(EXTRA, '/application/another/extra.jar')]}
    assert projected_components(document, module())[0] == {LIB}


def test_multiple_versions_of_same_library_keep_gav_and_version_coverage_separate():
    document = {'components': [component(LIB, PREFIX + 'library.jar'),
                                component('pkg:maven/example/library@3', PREFIX + 'duplicate.jar')]}
    row = score_module(document, module())
    assert row['versions']['version_accuracy_matched_identity'] == 1
    assert row['known_delivered_conservative']['precision'] == .5
    assert row['extra_conservatively_charged_fp'] == ['pkg:maven/example/library@3']

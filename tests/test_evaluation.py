import json
import time

import pytest
from fastapi.testclient import TestClient

from sbom_creator.acquire import Settings
from sbom_creator.evaluation import compare
from sbom_creator.service import Request, create_app


def test_request_modes_do_not_mix_reference_and_production():
    args = {'repository_url': 'https://example.com/r.git', 'commit': 'a' * 40, 'image': 'example.com/app:1'}
    assert Request(**args).run_mode == 'production'
    with pytest.raises(ValueError):
        Request(**args, reference_sbom={})
    with pytest.raises(ValueError):
        Request(**args, run_mode='verification')


def test_reference_only_evaluates_completed_direct_edges(tmp_path):
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
           'metadata': {'component': {'type': 'application', 'name': 'app', 'version': '1',
                                     'bom-ref': 'root', 'purl': 'pkg:npm/app@1'}},
           'components': [{'type': 'library', 'name': 'dep', 'version': '2', 'bom-ref': 'dep', 'purl': 'pkg:npm/dep@2'}],
           'dependencies': [{'ref': 'root', 'dependsOn': ['dep']}]}
    actual = dict(bom, components=[bom['metadata']['component'], *bom['components']])
    (tmp_path / 'final.cdx.json').write_text(json.dumps(actual))
    direct = {'status': 'available', 'edges': [{'status': 'DIRECT', 'owner_ref': 'root', 'component_ref': 'dep'}]}
    (tmp_path / 'direct-dependencies.json').write_text(json.dumps(direct))
    assert compare(tmp_path, bom)['status'] == 'UNKNOWN'
    result = compare(tmp_path, bom, 'runtime')
    assert (result['tp'], result['fp'], result['fn']) == (1, 0, 0)
    assert result['reference_used_as_analysis_input'] is False
    assert result['version_accuracy'] == 1
    actual['components'][1] = dict(actual['components'][1], purl='pkg:npm/dep@3')
    (tmp_path / 'final.cdx.json').write_text(json.dumps(actual))
    mismatch = compare(tmp_path, bom, 'runtime')
    assert (mismatch['tp'], mismatch['fp'], mismatch['fn']) == (0, 1, 1)
    assert mismatch['version_accuracy'] == 0
    assert mismatch['count_delta'] == 0
    assert mismatch['missing'] and mismatch['extra']


def test_api_reference_never_reaches_runner(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    events = []
    def runner(*args, **kwargs):
        assert set(kwargs) == {'settings', 'mode'}
        events.append('analysis')
        args[3].mkdir()
        return {'status': 'succeeded'}
    def evaluation(*args):
        assert events == ['analysis']
        events.append('evaluation')
        return {'status': 'UNKNOWN', 'reason': 'scope_not_established'}
    monkeypatch.setattr('sbom_creator.service.compare', evaluation)
    settings = Settings(bitbucket_hosts=('example.com',), registry_hosts=('registry.example',))
    payload = {'repository_url': 'https://example.com/r.git', 'commit': 'a' * 40,
               'image': 'registry.example/app:1', 'run_mode': 'verification',
               'reference_sbom': {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1}}
    headers = {'Authorization': 'Bearer token'}
    with TestClient(create_app(tmp_path, runner=runner, settings=settings)) as client:
        response = client.post('/v1/analyses', json=payload, headers=headers)
        assert response.status_code == 202
        for _ in range(100):
            state = client.get(response.json()['status_url'], headers=headers).json()
            if state['status'] not in ('queued', 'running'):
                break
            time.sleep(0.01)
        assert state['status'] == 'succeeded'
        assert 'evaluation.json' in state['artifacts']
        artifact = client.get(response.json()['status_url'] + '/artifacts/evaluation.json', headers=headers)
        assert artifact.status_code == 200
        assert events == ['analysis', 'evaluation']


def test_nested_reference_edges_and_dangling_targets(tmp_path):
    root = {'type': 'application', 'name': 'app', 'version': '1',
            'bom-ref': 'root', 'purl': 'pkg:npm/app@1'}
    dep = {'type': 'library', 'name': 'dep', 'version': '2',
           'bom-ref': 'dep', 'purl': 'pkg:npm/dep@2'}
    reference = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                 'metadata': {'component': dict(root, components=[dep])},
                 'dependencies': [{'ref': 'root', 'dependsOn': ['dep']}]}
    actual = dict(reference, metadata={'component': root}, components=[dep])
    (tmp_path / 'final.cdx.json').write_text(json.dumps(actual))
    report = {'status': 'available', 'edges': [
        {'status': 'DIRECT', 'owner_ref': 'root', 'component_ref': 'dep'}]}
    (tmp_path / 'direct-dependencies.json').write_text(json.dumps(report))
    assert compare(tmp_path, reference, 'runtime')['tp'] == 1
    report['edges'][0]['component_ref'] = 'missing'
    (tmp_path / 'direct-dependencies.json').write_text(json.dumps(report))
    assert compare(tmp_path, reference, 'runtime')['reason'] == 'analyzer_dependency_target_unavailable'
    reference['dependencies'][0]['dependsOn'] = ['missing']
    with pytest.raises(ValueError, match='Dangling CycloneDX dependency'):
        compare(tmp_path, reference, 'runtime')


def inventory_bom(*purls, subject='pkg:maven/org/app@1'):
    from packageurl import PackageURL
    def component(purl, ref):
        identity = PackageURL.from_string(purl)
        item = {'type': 'library', 'name': identity.name, 'version': identity.version,
                'purl': purl, 'bom-ref': ref}
        if identity.namespace:
            item['group'] = identity.namespace
        return item
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': component(subject, 'subject')},
            'components': [component(p, 'dep-'+str(i)) for i, p in enumerate(purls)]}


def test_image_only_components_are_measured_when_direct_owner_unknown(tmp_path):
    reference = inventory_bom('pkg:maven/org/a@1', 'pkg:maven/org/b@2')
    actual = inventory_bom('pkg:maven/org/a@1', 'pkg:maven/org/extra@3', subject='pkg:oci/image@1')
    (tmp_path/'final.cdx.json').write_text(json.dumps(actual))
    result = compare(tmp_path, reference, 'runtime')
    assert result['status'] == 'UNKNOWN' and result['precision'] is None
    metrics = result['components']
    assert metrics['status'] == 'MEASURED'
    assert (metrics['tp'], metrics['fp'], metrics['fn']) == (1, 1, 1)
    assert metrics['precision'] == metrics['recall'] == metrics['f1'] == 0.5
    assert metrics['count_delta'] == 0 and metrics['missing'] and metrics['extra']
    assert metrics['comparison_model'] == 'delivered_inventory'
    assert metrics['reference_scope_binding'] == 'caller_asserted_not_attested'


@pytest.mark.parametrize('actual_purl', [
    'pkg:maven/org/a@1?classifier=tests', 'pkg:maven/org/a@1#classes', 'pkg:maven/org/a@2'])
def test_component_comparison_retains_qualifiers_subpaths_and_exact_versions(tmp_path, actual_purl):
    reference = inventory_bom('pkg:maven/org/a@1')
    (tmp_path/'final.cdx.json').write_text(json.dumps(inventory_bom(actual_purl)))
    metrics = compare(tmp_path, reference, 'runtime')['components']
    assert (metrics['tp'], metrics['fp'], metrics['fn']) == (0, 1, 1)
    assert metrics['exact_version_coverage'] == 0
    assert metrics['count_delta'] == 0


def test_component_version_accuracy_is_conditional_and_recall_counts_missing_versions(tmp_path):
    reference = inventory_bom('pkg:maven/org/a@1', 'pkg:maven/org/b@1')
    (tmp_path/'final.cdx.json').write_text(json.dumps(inventory_bom('pkg:maven/org/a@1')))
    metrics = compare(tmp_path, reference, 'runtime')['components']
    assert metrics['version_accuracy'] == 1 and metrics['exact_version_coverage'] == 0.5


def test_component_subject_excluded_in_components_and_nested_dependencies_retained(tmp_path):
    reference = inventory_bom('pkg:maven/org/a@1')
    reference['metadata']['component']['components'] = reference.pop('components')
    actual = inventory_bom('pkg:maven/org/a@1')
    actual['components'].append(dict(actual['metadata']['component'], **{'bom-ref': 'copied-subject'}))
    (tmp_path/'final.cdx.json').write_text(json.dumps(actual))
    metrics = compare(tmp_path, reference, 'runtime')['components']
    assert (metrics['tp'], metrics['fp'], metrics['fn']) == (1, 0, 0)
    assert metrics['predicted_components'] == 1


def test_unscoped_reference_cannot_label_runtime_inventory(tmp_path):
    reference = inventory_bom('pkg:maven/org/a@1')
    (tmp_path/'final.cdx.json').write_text(json.dumps(reference))
    result = compare(tmp_path, reference)
    assert result['components']['status'] == 'UNKNOWN'
    assert result['components']['precision'] is None


def test_build_comparison_never_uses_image_final_as_build_inventory(tmp_path):
    reference = inventory_bom('pkg:maven/org/build-only@1')
    (tmp_path/'final.cdx.json').write_text(json.dumps(inventory_bom('pkg:maven/org/image-only@1')))
    assert compare(tmp_path, reference, 'build')['components']['status'] == 'UNKNOWN'
    (tmp_path/'build.cdx.json').write_text(json.dumps(reference))
    result = compare(tmp_path, reference, 'build')['components']
    assert result['tp'] == 1 and result['fp'] == 0
    assert result['comparison_model'] == 'analysis_environment_build_model'
    assert result['original_build_reproduced'] is False


def test_empty_and_unidentifiable_reference_inventory_is_not_success(tmp_path):
    empty = inventory_bom()
    (tmp_path/'final.cdx.json').write_text(json.dumps(empty))
    metrics = compare(tmp_path, empty, 'runtime')['components']
    assert metrics['status'] == 'UNKNOWN' and metrics['recall'] is None
    unknown = inventory_bom('pkg:maven/org/a@1')
    unknown['components'][0].pop('purl')
    metrics = compare(tmp_path, unknown, 'runtime')['components']
    assert metrics['status'] == 'UNKNOWN' and metrics['reference_unknown_components'] == 1
    assert metrics['precision'] is None


def test_contradictory_component_version_is_unknown_not_a_successful_match(tmp_path):
    reference = inventory_bom('pkg:maven/org/a@1')
    actual = inventory_bom('pkg:maven/org/a@1')
    actual['components'][0]['version'] = 'different'
    (tmp_path/'final.cdx.json').write_text(json.dumps(actual))
    metrics = compare(tmp_path, reference, 'runtime')['components']
    assert metrics['status'] == 'UNKNOWN' and metrics['predicted_unknown_components'] == 1


def test_cyclonedx_17_requires_explicit_peer_opt_in_and_checks_graph_integrity():
    from sbom_creator.validation import validate_cyclonedx
    peer = inventory_bom('pkg:maven/org/a@1')
    peer['specVersion'] = '1.7'
    with pytest.raises(ValueError, match='Unsupported CycloneDX version'):
        validate_cyclonedx(peer)
    validate_cyclonedx(peer, versions=('1.6', '1.7'))
    peer['dependencies'] = [{'ref': 'subject', 'dependsOn': ['missing']}]
    with pytest.raises(ValueError, match='Dangling CycloneDX dependency'):
        validate_cyclonedx(peer, versions=('1.6', '1.7'))

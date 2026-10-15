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

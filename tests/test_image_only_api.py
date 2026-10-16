"""Image-first API contract and strict separation of optional source/reference inputs."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from sbom_creator.acquire import Settings
from sbom_creator.service import Request, create_app

SETTINGS = Settings(registry_hosts=('registry.example',))
IMAGE = 'registry.example/app@sha256:'+'a'*64
HEADERS = {'Authorization': 'Bearer token'}


def completed(client, path):
    for _ in range(100):
        state = client.get(path, headers=HEADERS).json()
        if state['status'] not in ('queued', 'running'):
            return state
        time.sleep(0.01)
    pytest.fail('Analysis did not terminate')


def test_image_only_api_needs_no_repository_allowlist_and_publishes_audit(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    monkeypatch.setenv('SBOM_DEBUG_LOGGING', 'true')
    calls = []
    def runner(url, commit, image, output, **kwargs):
        calls.append((url, commit, image))
        assert set(kwargs) == {'settings', 'mode'}
        output.mkdir()
        for name in ('final.cdx.json', 'image-identity-audit.json'):
            (output/name).write_text('{}')
        return {'status': 'succeeded', 'partial': True}
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={'image': IMAGE}, headers=HEADERS)
        assert response.status_code == 202
        path = response.json()['status_url']
        state = completed(client, path)
        assert state['status'] == 'succeeded' and state['result']['partial'] is True
        assert 'image-identity-audit.json' in state['artifacts']
        assert 'build.cdx.json' not in state['artifacts']
        assert client.get(path+'/artifacts/image-identity-audit.json', headers=HEADERS).status_code == 200
        assert client.get(path+'/artifacts/../status.json', headers=HEADERS).status_code == 404
    assert calls == [(None, None, IMAGE)]


@pytest.mark.parametrize('source', [
    {'repository_url': 'https://example.com/repo.git'}, {'commit': 'b'*40}])
def test_partial_source_identity_rejected_before_any_job(tmp_path, monkeypatch, source):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    def runner(*args, **kwargs):
        pytest.fail('Invalid source identity reached analyzer')
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={'image': IMAGE, **source}, headers=HEADERS)
        assert response.status_code == 422
        assert not list((tmp_path/'jobs').iterdir())


def test_image_only_verification_reference_arrives_only_after_prediction(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    events = []
    reference = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1}
    def runner(url, commit, image, output, **kwargs):
        assert (url, commit, image) == (None, None, IMAGE)
        assert set(kwargs) == {'settings', 'mode'}
        events.append('prediction')
        output.mkdir()
        (output/'final.cdx.json').write_text('{}')
        return {'status': 'succeeded'}
    def evaluate(output, oracle, scope):
        assert events == ['prediction'] and (output/'final.cdx.json').is_file()
        assert oracle == reference and scope == 'runtime'
        events.append('evaluation')
        return {'status': 'UNKNOWN', 'reason': 'no_direct_owner_labels'}
    monkeypatch.setattr('sbom_creator.service.compare', evaluate)
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={
            'image': IMAGE, 'run_mode': 'verification', 'reference_sbom': reference,
            'reference_scope': 'runtime'}, headers=HEADERS)
        assert response.status_code == 202
        path = response.json()['status_url']
        state = completed(client, path)
        assert state['status'] == 'succeeded'
        result = client.get(path+'/artifacts/evaluation.json', headers=HEADERS)
        assert json.loads(result.text)['status'] == 'UNKNOWN'
    assert events == ['prediction', 'evaluation']


def test_image_only_production_does_not_accept_reference():
    with pytest.raises(ValueError, match='Production mode'):
        Request(image=IMAGE, reference_sbom={})


def test_image_only_pipeline_skips_checkout_and_source_build_tools(tmp_path, monkeypatch):
    from sbom_creator import pipeline
    events = []
    def source(path, output, settings):
        assert path.is_dir() and not list(path.iterdir())
        events.append('empty-source')
        return {'artifacts': []}
    monkeypatch.setattr(pipeline, 'scan_source', source)
    monkeypatch.setattr(pipeline, 'checkout', lambda *a: pytest.fail('Image-only analysis checked out source'))
    monkeypatch.setattr(pipeline, 'resolve_java', lambda *a: pytest.fail('Image-only analysis executed source tooling'))
    def image(reference, output, settings):
        assert reference == IMAGE
        events.append('image')
        return {'artifacts': []}, {'immutable_reference': IMAGE}
    monkeypatch.setattr(pipeline, 'scan_image', image)
    def publish(source, image, output, settings, assessor, provenance, *args):
        assert provenance['source_kind'] == 'not-provided' and not args
        events.append('publish')
        return {'status': 'succeeded'}
    monkeypatch.setattr(pipeline, 'publish_catalogs', publish)
    assert pipeline.analyze(None, None, IMAGE, tmp_path/'result', settings=SETTINGS)['status'] == 'succeeded'
    assert events == ['empty-source', 'image', 'publish']


def test_image_only_verification_downloads_measured_component_metrics_without_direct_graph(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    component = {'type': 'library', 'name': 'delivered', 'version': '1',
                 'bom-ref': 'delivered', 'purl': 'pkg:maven/org/delivered@1', 'group': 'org'}
    reference = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                 'components': [component]}
    def runner(url, commit, image, output, **kwargs):
        assert url is None and commit is None
        assert set(kwargs) == {'settings', 'mode'}
        output.mkdir()
        (output/'final.cdx.json').write_text(json.dumps(reference))
        return {'status': 'succeeded'}
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={'image': IMAGE, 'run_mode': 'verification',
            'reference_sbom': reference, 'reference_scope': 'runtime'}, headers=HEADERS)
        assert response.status_code == 202
        path = response.json()['status_url']
        state = completed(client, path)
        assert state['status'] == 'succeeded'
        evaluation = client.get(path+'/artifacts/evaluation.json', headers=HEADERS).json()
        assert evaluation['status'] == 'UNKNOWN' and evaluation['precision'] is None
        assert evaluation['components']['status'] == 'MEASURED'
        assert evaluation['components']['tp'] == 1
        assert evaluation['components']['precision'] == evaluation['components']['recall'] == 1

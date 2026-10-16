"""HTTP source/image independence with deterministic engines and registry readiness."""
import hashlib
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from sbom_creator.acquire import Settings
from sbom_creator.service import create_app

SETTINGS = Settings(bitbucket_hosts=('github.com',), registry_hosts=('registry.example',),
                    source_image_poll_interval=1, source_image_wait_timeout=10)
REQUEST = {'repository_url': 'https://github.com/example/project.git', 'commit': 'a' * 40}
IMAGE = 'registry.example/project@sha256:' + 'b' * 64
HEADERS = {'Authorization': 'Bearer test-token'}


def _write(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


def _bom():
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'components': [{'type': 'library', 'name': 'example', 'version': '1',
                            'bom-ref': 'dep', 'purl': 'pkg:npm/example@1'}],
            'dependencies': [{'ref': 'dep', 'dependsOn': []}]}


def _source(url, commit, output, **kwargs):
    output.mkdir()
    _write(output / 'source.cdx.json', _bom())
    _write(output / 'source-provenance.json', {'repository_url': url, 'commit': commit,
        'source_sbom_sha256': hashlib.sha256((output / 'source.cdx.json').read_bytes()).hexdigest()})
    _write(output / 'source-summary.json', {'status': 'completed'})


def _image(url, commit, image, output, **kwargs):
    assert url is commit is None  # Source graph never alters the independent image inventory.
    assert image == IMAGE
    output.mkdir()
    for name in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
        _write(output / name, _bom())
    _write(output / 'provenance.json', {'request': {'image': image}, 'image': {
        'image': image, 'immutable_reference': image, 'image_config_digest': 'sha256:' + 'c' * 64}})
    return {'status': 'succeeded', 'partial': False}


def _until(client, path, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(path, headers=HEADERS)
        assert response.status_code == 200
        state = response.json()
        if predicate(state):
            return state
        time.sleep(0.01)
    pytest.fail('Workflow did not reach its expected bounded state')


def test_source_download_precedes_image_and_attach_creates_separate_job(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')
    probes = []

    def probe(image, settings):
        probes.append(image)
        return {'status': 'available', 'immutable_image': IMAGE}

    with TestClient(create_app(tmp_path, _image, SETTINGS, source_runner=_source,
                               image_probe=probe)) as client:
        response = client.post('/v1/source-analyses', json=REQUEST, headers=HEADERS)
        assert response.status_code == 202
        path = response.json()['status_url']
        state = _until(client, path, lambda state: state['source_status'] == 'succeeded')
        assert state['image_status'] == 'not_requested'
        assert not probes
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 200
        assert client.get(path + '/artifacts/full.cdx.json', headers=HEADERS).status_code == 404
        assert client.get(path + '/comparison', headers=HEADERS).status_code == 409
        response = client.post(path + '/image', json={'image': 'registry.example/project:future'},
                               headers=HEADERS)
        assert response.status_code == 202
        state = _until(client, path, lambda state: state['comparison_status'] == 'succeeded')
        child = state['image']['status_url']
        assert child.startswith('/v1/analyses/')
        assert client.get(child + '/artifacts/full.cdx.json', headers=HEADERS).status_code == 200
        comparison = client.get(path + '/comparison', headers=HEADERS).json()
        assert comparison['shared'] == ['pkg:npm/example@1']
        assert comparison['source_only'] == comparison['image_only'] == []
        assert comparison['original_ci_graph_reproduced'] is False


def test_waiting_image_does_not_delay_source_or_occupy_image_executor(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')
    probed = threading.Event()

    def unavailable(*args):
        probed.set()
        return {'status': 'waiting'}

    with TestClient(create_app(tmp_path, _image, SETTINGS, source_runner=_source,
                               image_probe=unavailable)) as client:
        accepted = client.post('/v1/source-analyses', json=dict(REQUEST,
            image='registry.example/project:future'), headers=HEADERS).json()
        path = accepted['status_url']
        state = _until(client, path, lambda state: state['source_status'] == 'succeeded')
        assert probed.wait(1)
        assert state['image_status'] == 'waiting'
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 200
        assert client.post(path + '/image', json={'image': IMAGE}, headers=HEADERS).status_code == 409
        child = client.post('/v1/analyses', json={'image': IMAGE}, headers=HEADERS).json()['status_url']
        _until(client, child, lambda state: state['status'] == 'succeeded')


def test_source_failure_does_not_block_image_and_errors_are_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')

    def failed(*args, **kwargs):
        raise RuntimeError('secret-value-not-public')

    with TestClient(create_app(tmp_path, _image, SETTINGS, source_runner=failed,
             image_probe=lambda *args: {'status': 'available', 'immutable_image': IMAGE})) as client:
        path = client.post('/v1/source-analyses', json=dict(REQUEST, image=IMAGE),
                           headers=HEADERS).json()['status_url']
        state = _until(client, path, lambda state: state['image_status'] == 'succeeded'
                       and state['comparison_status'] == 'skipped')
        assert state['source_status'] == 'failed'
        assert 'secret-value' not in json.dumps(state)
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 409
        assert client.get(state['image']['status_url'] + '/artifacts/final.cdx.json',
                          headers=HEADERS).status_code == 200


def test_source_api_auth_validation_and_no_reference_contract(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')
    with TestClient(create_app(tmp_path, settings=SETTINGS, source_runner=_source)) as client:
        assert client.post('/v1/source-analyses', json=REQUEST).status_code == 401
        assert client.get('/v1/source-analyses/invalid', headers=HEADERS).status_code == 404
        for request in ({'repository_url': REQUEST['repository_url']},
                        dict(REQUEST, reference_sbom={}), dict(REQUEST, proof={}),
                        dict(REQUEST, repository_url='https://foreign.example/repo.git'),
                        dict(REQUEST, image='foreign.example/repo:1')):
            assert client.post('/v1/source-analyses', json=request, headers=HEADERS).status_code == 422


def test_archive_cli_configuration_does_not_block_source_only(tmp_path, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')
    configured = Settings(bitbucket_hosts=('github.com',), registry_hosts=('registry.example',),
                          image_archive='operator-local-archive.tar')
    with TestClient(create_app(tmp_path, settings=configured, source_runner=_source)) as client:
        path = client.post('/v1/source-analyses', json=REQUEST,
                           headers=HEADERS).json()['status_url']
        _until(client, path, lambda state: state['source_status'] == 'succeeded')
        assert client.post(path + '/image', json={'image': IMAGE}, headers=HEADERS).status_code == 503
        assert client.post('/v1/source-analyses', json=dict(REQUEST, image=IMAGE),
                           headers=HEADERS).status_code == 503

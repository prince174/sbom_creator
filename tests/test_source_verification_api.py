"""Reference evaluation is strictly post-publication and never needs an image."""
import hashlib
import json
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from sbom_creator import evaluation, source_workflows
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import write_json
from sbom_creator.service import create_app
from sbom_creator.source_workflows import SOURCE_ARTIFACTS, SourceWorkflows

REQUEST = {'repository_url': 'https://github.com/example/project.git', 'commit': 'a' * 40}
SETTINGS = Settings(bitbucket_hosts=('github.com',), registry_hosts=('registry.example',))
HEADERS = {'Authorization': 'Bearer test-token'}


def _bom():
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': 'project',
                                      'version': '1', 'bom-ref': 'project',
                                      'purl': 'pkg:npm/project@1'},
                         'tools': {'components': [{'type': 'application', 'name': 'cdxgen',
                                                    'version': '13.4.0'}]}},
            'components': [{'type': 'library', 'name': 'example', 'version': '1',
                            'bom-ref': 'dep', 'purl': 'pkg:npm/example@1'}],
            'dependencies': [{'ref': 'project', 'dependsOn': ['dep']},
                             {'ref': 'dep', 'dependsOn': []}]}


def _source(url, commit, output, **kwargs):
    assert set(kwargs) == {'settings'}
    output.mkdir()
    write_json(output / 'source.cdx.json', _bom())
    write_json(output / 'source-provenance.json', {
        'repository_url': url, 'commit': commit, 'requested_commit': commit,
        'source_sbom_sha256': hashlib.sha256((output / 'source.cdx.json').read_bytes()).hexdigest(),
        'reference_used_as_input': False, 'original_build_reproduced': False,
        'image_input_used': False,
        'engine': {'name': 'cdxgen', 'version': '13.4.0', 'image_id': 'sha256:' + 'd' * 64}})
    write_json(output / 'source-summary.json', {'status': 'completed',
        'result_kind': 'source_model', 'original_build_reproduced': False,
        'image_presence_verified': False, 'reference_used_as_input': False})


def _forbidden(*args, **kwargs):
    pytest.fail('Evaluation must not invoke checkout, build, scanner or image submission')


def _wait(client, path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = client.get(path, headers=HEADERS)
        assert result.status_code == 200
        if result.json()['source_status'] in ('succeeded', 'failed'):
            return result.json()
        time.sleep(0.005)
    pytest.fail('Source publication did not finish')


def _submit(client, *, image=None):
    request = dict(REQUEST)
    if image is not None:
        request['image'] = image
    result = client.post('/v1/source-analyses', json=request, headers=HEADERS)
    assert result.status_code == 202
    assert _wait(client, result.json()['status_url'])['source_status'] == 'succeeded'
    return result.json()


@pytest.fixture
def evaluator(monkeypatch):
    calls = []

    def evaluate(directory, reference, scope, *, reference_commit=None):
        calls.append((directory, reference, scope, reference_commit))
        evaluation.validate_reference(reference)
        if reference_commit is not None and reference_commit.lower() != REQUEST['commit']:
            raise ValueError('Do not expose caller reference or private path')
        return {'status': 'completed', 'kind': 'source_model_evaluation',
                'reference_used_as_analysis_input': False,
                'source_binding': {'commit': REQUEST['commit']},
                'reference_binding': {'scope': scope, 'provenance': 'caller_asserted'}}

    monkeypatch.setattr(source_workflows, '_evaluate_source', evaluate)
    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')
    return calls


def test_source_only_evaluation_has_exact_post_binding_order_and_never_forwards_reference(
        tmp_path, monkeypatch, evaluator):
    events, runner_calls = [], []
    original_binding = SourceWorkflows._source_binding
    original_validate = evaluation.validate_reference

    def binding(self, directory, state):
        events.append('source_binding')
        return original_binding(self, directory, state)

    def validate(reference):
        events.append('reference_validation')
        return original_validate(reference)

    def runner(*args, **kwargs):
        runner_calls.append((args, kwargs))
        return _source(*args, **kwargs)

    monkeypatch.setattr(SourceWorkflows, '_source_binding', binding)
    monkeypatch.setattr(evaluation, 'validate_reference', validate)
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=runner,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        source = client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).content
        events.clear()
        response = client.post(path + '/evaluations', json={
            'reference_sbom': _bom(), 'reference_scope': 'build',
            'reference_commit': REQUEST['commit']}, headers=HEADERS)
        assert response.status_code == 201
        assert events == ['source_binding', 'reference_validation', 'source_binding']
        record = response.json()
        assert record['source_analysis_id'] == accepted['id']
        assert str(uuid.UUID(record['id'])) == record['id']
        report = client.get(record['evaluation_url'], headers=HEADERS)
        assert report.status_code == 200
        assert report.json()['id'] == record['id']
        assert report.json()['publication_binding']['source_sbom_sha256'] == hashlib.sha256(source).hexdigest()
        reference = (tmp_path / 'source-jobs' / accepted['id'] / 'evaluations'
                     / record['id'] / 'reference.cdx.json')
        assert report.json()['publication_binding']['reference_artifact_sha256'] == hashlib.sha256(reference.read_bytes()).hexdigest()
        assert json.loads(reference.read_text()) == _bom()
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).content == source
        status = client.get(path, headers=HEADERS).json()
        assert status['image_status'] == 'not_requested'
        assert 'reference_sbom' not in status and 'evaluations' not in status
    assert len(runner_calls) == len(evaluator) == 1
    assert runner_calls[0][0][:2] == (REQUEST['repository_url'], REQUEST['commit'])
    assert set(runner_calls[0][1]) == {'settings'}
    assert evaluator[0][2:] == ('build', REQUEST['commit'])


def test_reference_schema_is_not_validated_before_source_publication(tmp_path, monkeypatch, evaluator):
    entered, release = threading.Event(), threading.Event()

    def runner(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return _source(*args, **kwargs)

    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=runner,
                               image_probe=_forbidden)) as client:
        accepted = client.post('/v1/source-analyses', json=REQUEST, headers=HEADERS).json()
        try:
            assert entered.wait(2)
            response = client.post(accepted['status_url'] + '/evaluations',
                                   json={'reference_sbom': {'invalid': True}}, headers=HEADERS)
            assert response.status_code == 409
            assert evaluator == []
        finally:
            release.set()
        assert _wait(client, accepted['status_url'])['source_status'] == 'succeeded'
        response = client.post(accepted['status_url'] + '/evaluations',
                               json={'reference_sbom': {'invalid': True}}, headers=HEADERS)
        assert response.status_code == 422
        assert len(evaluator) == 1


def test_invalid_source_binding_is_rejected_before_reference_processing(tmp_path, evaluator):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = tmp_path / 'source-jobs' / accepted['id'] / 'source/source-provenance.json'
        provenance = json.loads(path.read_text())
        provenance['commit'] = 'b' * 40
        write_json(path, provenance)
        response = client.post(accepted['status_url'] + '/evaluations',
                               json={'reference_sbom': {'invalid': True}}, headers=HEADERS)
        assert response.status_code == 503
        assert evaluator == []
        assert client.get(accepted['status_url'] + '/artifacts/source.cdx.json',
                          headers=HEADERS).status_code == 200


def test_multiple_evaluations_are_immutable_and_survive_restart(tmp_path, evaluator):
    app = lambda: create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                             image_probe=_forbidden)
    with TestClient(app()) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        first = client.post(path + '/evaluations', json={'reference_sbom': _bom()},
                            headers=HEADERS).json()
        first_bytes = client.get(first['evaluation_url'], headers=HEADERS).content
        second = client.post(path + '/evaluations', json={'reference_sbom': _bom(),
                             'reference_scope': 'runtime'}, headers=HEADERS).json()
        assert first['id'] != second['id']
        assert client.get(first['evaluation_url'], headers=HEADERS).content == first_bytes
    with TestClient(app()) as client:
        assert client.get(first['evaluation_url'], headers=HEADERS).content == first_bytes
        assert client.get(second['evaluation_url'], headers=HEADERS).status_code == 200
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 200
    assert len(evaluator) == 2


@pytest.mark.parametrize('body', [
    {'reference_sbom': {'secret': 'never-echo-this'}},
    {'reference_sbom': _bom(), 'reference_commit': 'b' * 40},
    {'reference_sbom': _bom(), 'reference_commit': 'main'},
    {'reference_sbom': _bom(), 'reference_scope': 'attested'},
    {'reference_sbom': _bom(), 'proof': {'caller_attested': True}}])
def test_bad_reference_commit_or_caller_proof_never_alters_source(tmp_path, evaluator, body):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        original = client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).content
        response = client.post(path + '/evaluations', json=body, headers=HEADERS)
        assert response.status_code == 422
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).content == original
        assert not (tmp_path / 'source-jobs' / accepted['id'] / 'evaluations').exists()


def test_production_source_request_rejects_reference_and_proof(tmp_path, evaluator):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_forbidden,
                               image_probe=_forbidden)) as client:
        for extra in ({'reference_sbom': _bom()}, {'proof': {'scope': 'attested'}}):
            result = client.post('/v1/source-analyses', json=dict(REQUEST, **extra), headers=HEADERS)
            assert result.status_code == 422
        assert evaluator == []
        assert list((tmp_path / 'source-jobs').iterdir()) == []


def test_evaluation_capacity_does_not_block_source_downloads(tmp_path, monkeypatch, evaluator):
    entered, release, response = threading.Event(), threading.Event(), []
    original = source_workflows._evaluate_source
    original_binding, binding_calls = SourceWorkflows._source_binding, []

    def binding(*args, **kwargs):
        binding_calls.append(1)
        return original_binding(*args, **kwargs)

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(source_workflows, '_evaluate_source', blocked)
    monkeypatch.setattr(SourceWorkflows, '_source_binding', binding)
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        binding_calls.clear()
        path = accepted['status_url']
        thread = threading.Thread(target=lambda: response.append(client.post(path + '/evaluations',
            json={'reference_sbom': _bom()}, headers=HEADERS)))
        thread.start()
        try:
            assert entered.wait(2)
            busy = client.post(path + '/evaluations', json={'reference_sbom': _bom()}, headers=HEADERS)
            assert busy.status_code == 429
            assert binding_calls == [1]  # Busy requests also avoid expensive source validation.
            assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 200
        finally:
            release.set()
            thread.join(3)
        assert response[0].status_code == 201
        assert len(evaluator) == 1


def test_evaluation_while_image_waits_does_not_submit_image_or_change_source(tmp_path, evaluator):
    probed = threading.Event()

    def waiting(*args):
        probed.set()
        return {'status': 'waiting'}

    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=waiting)) as client:
        accepted = _submit(client, image='registry.example/project:future')
        assert probed.wait(2)
        path = accepted['status_url']
        response = client.post(path + '/evaluations', json={'reference_sbom': _bom()}, headers=HEADERS)
        assert response.status_code == 201
        state = client.get(path, headers=HEADERS).json()
        assert state['source_status'] == 'succeeded' and state['image_status'] == 'waiting'
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 200
        assert not list((tmp_path / 'jobs').iterdir())


@pytest.mark.parametrize('fault', ['write', 'commit', 'engine'])
def test_evaluation_faults_are_redacted_and_preserve_all_source_files(
        tmp_path, monkeypatch, evaluator, fault, caplog):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        source = tmp_path / 'source-jobs' / accepted['id'] / 'source'
        originals = {name: (source / name).read_bytes() for name in SOURCE_ARTIFACTS}

        def failed(*args, **kwargs):
            raise PermissionError('service-secret-and-private-path')

        attribute = {'write': 'write_json', 'commit': 'commit_directory',
                     'engine': '_evaluate_source'}[fault]
        with monkeypatch.context() as context:
            context.setattr(source_workflows, attribute, failed)
            result = client.post(path + '/evaluations', json={'reference_sbom': _bom()}, headers=HEADERS)
            assert result.status_code == 503
            assert 'service-secret' not in result.text + caplog.text
        assert {name: (source / name).read_bytes() for name in SOURCE_ARTIFACTS} == originals
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).status_code == 200
        # Capacity is released even when validation or publication fails.
        assert client.post(path + '/evaluations', json={'reference_sbom': _bom()},
                           headers=HEADERS).status_code == 201


def test_existing_evaluation_target_cannot_be_replaced(tmp_path, monkeypatch, evaluator):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        first = client.post(path + '/evaluations', json={'reference_sbom': _bom()}, headers=HEADERS).json()
        original = client.get(first['evaluation_url'], headers=HEADERS).content
        with monkeypatch.context() as context:
            context.setattr(source_workflows.uuid, 'uuid4', lambda: uuid.UUID(first['id']))
            second = client.post(path + '/evaluations', json={'reference_sbom': _bom()}, headers=HEADERS)
        assert second.status_code == 503
        assert client.get(first['evaluation_url'], headers=HEADERS).content == original


def test_cleanup_failure_after_evaluation_commit_keeps_downloadable_success(
        tmp_path, monkeypatch, evaluator, caplog):
    temporary = source_workflows.tempfile.TemporaryDirectory

    class CleanupFailure:
        def __init__(self, *args, **kwargs):
            self.wrapped = temporary(*args, **kwargs)
            self.name = self.wrapped.name

        def cleanup(self):
            self.wrapped.cleanup()
            raise PermissionError('private-cleanup-detail')

    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        with monkeypatch.context() as context:
            context.setattr(source_workflows.tempfile, 'TemporaryDirectory', CleanupFailure)
            response = client.post(accepted['status_url'] + '/evaluations',
                                   json={'reference_sbom': _bom()}, headers=HEADERS)
        assert response.status_code == 201
        assert client.get(response.json()['evaluation_url'], headers=HEADERS).status_code == 200
        assert 'source_evaluation.cleanup_failed' in caplog.text
        assert 'private-cleanup-detail' not in caplog.text


def test_evaluation_auth_uuid_and_download_boundaries(tmp_path, evaluator):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        assert client.post(path + '/evaluations', json={'reference_sbom': _bom()}).status_code == 401
        assert client.get(path + '/evaluations/' + str(uuid.uuid4())).status_code == 401
        for invalid in ('not-a-uuid', 'a' * 40, str(uuid.uuid4())):
            assert client.get(path + '/evaluations/' + invalid, headers=HEADERS).status_code == 404
        assert client.post('/v1/source-analyses/not-a-uuid/evaluations',
                           json={'reference_sbom': _bom()}, headers=HEADERS).status_code == 404
        completed = client.post(path + '/evaluations', json={'reference_sbom': _bom()}, headers=HEADERS).json()
        # Audit reference and arbitrary files are not exposed by either artifact route.
        assert client.get(path + '/artifacts/reference.cdx.json', headers=HEADERS).status_code == 404
        assert client.get(completed['evaluation_url'] + '/reference.cdx.json', headers=HEADERS).status_code == 404


def test_reference_budget_is_enforced_only_after_prediction(tmp_path, evaluator):
    oversized = _bom()
    oversized['metadata']['component']['description'] = 'x' * (evaluation.LIMIT + 1)
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        response = client.post(accepted['status_url'] + '/evaluations',
                               json={'reference_sbom': oversized}, headers=HEADERS)
        assert response.status_code == 422
        assert client.get(accepted['status_url'] + '/artifacts/source.cdx.json',
                          headers=HEADERS).status_code == 200


@pytest.mark.parametrize('scope', ['build', 'unknown', 'runtime'])
def test_real_post_evaluator_scores_only_explicit_build_scope_without_any_image(
        tmp_path, monkeypatch, scope):
    from sbom_creator import acquire, scanner, source_analysis, source_evaluation

    monkeypatch.setenv('SBOM_API_TOKEN', 'test-token')
    calls = []

    def runner(*args, **kwargs):
        calls.append((args, kwargs))
        return _source(*args, **kwargs)

    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=runner,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        path = accepted['status_url']
        original = client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).content
        monkeypatch.setattr(acquire, 'checkout', _forbidden)
        monkeypatch.setattr(acquire, 'run_command', _forbidden)
        monkeypatch.setattr(source_analysis, 'analyze_source', _forbidden)
        monkeypatch.setattr(source_analysis, '_engine', _forbidden)
        monkeypatch.setattr(scanner, 'scan_image', _forbidden)
        monkeypatch.setattr(scanner, 'scan_source', _forbidden)
        evaluated = []
        actual = source_evaluation.evaluate_source

        def evaluator(*args, **kwargs):
            evaluated.append((args, kwargs))
            return actual(*args, **kwargs)

        monkeypatch.setattr(source_evaluation, 'evaluate_source', evaluator)
        response = client.post(path + '/evaluations', json={
            'reference_sbom': _bom(), 'reference_scope': scope,
            'reference_commit': REQUEST['commit']}, headers=HEADERS)
        assert response.status_code == 201
        report = client.get(response.json()['evaluation_url'], headers=HEADERS).json()
        assert report['analyzer_invoked'] is report['image_required'] is False
        assert report['original_ci_graph_reproduced'] is False
        assert report['reference_binding']['provenance'] == 'caller_asserted_not_attested'
        assert report['reference_binding']['commit_matches_source'] is True
        components = report['components']['exact_purl']
        graph = report['direct_dependencies']['exact_purl']
        if scope == 'build':
            assert report['status'] == 'MEASURED'
            assert (components['tp'], components['fp'], components['fn']) == (1, 0, 0)
            assert (graph['tp'], graph['fp'], graph['fn']) == (1, 0, 0)
            assert components['precision'] == components['recall'] == 1.0
            assert graph['precision'] == graph['recall'] == 1.0
        else:
            assert report['status'] == components['status'] == graph['status'] == 'UNKNOWN'
            assert components['precision'] is graph['precision'] is None
        assert client.get(path + '/artifacts/source.cdx.json', headers=HEADERS).content == original
        assert client.get(path, headers=HEADERS).json()['image_status'] == 'not_requested'
        assert len(calls) == len(evaluated) == 1
        assert set(calls[0][1]) == {'settings'}


def test_failed_source_cannot_be_evaluated_and_does_not_validate_reference(tmp_path, evaluator):
    def failed(*args, **kwargs):
        raise RuntimeError('private-checkout-failure')

    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=failed,
                               image_probe=_forbidden)) as client:
        accepted = client.post('/v1/source-analyses', json=REQUEST, headers=HEADERS).json()
        assert _wait(client, accepted['status_url'])['source_status'] == 'failed'
        response = client.post(accepted['status_url'] + '/evaluations',
                               json={'reference_sbom': {'not': 'a-sbom'}}, headers=HEADERS)
        assert response.status_code == 409
        assert evaluator == []


def test_evaluation_parent_must_be_an_owned_directory(tmp_path, evaluator):
    with TestClient(create_app(tmp_path, _forbidden, SETTINGS, source_runner=_source,
                               image_probe=_forbidden)) as client:
        accepted = _submit(client)
        parent = tmp_path / 'source-jobs' / accepted['id'] / 'evaluations'
        parent.write_text('preserve-unexpected-existing-object', encoding='utf-8')
        response = client.post(accepted['status_url'] + '/evaluations',
                               json={'reference_sbom': _bom()}, headers=HEADERS)
        assert response.status_code == 503
        assert parent.read_text() == 'preserve-unexpected-existing-object'
        assert client.get(accepted['status_url'] + '/artifacts/source.cdx.json',
                          headers=HEADERS).status_code == 200

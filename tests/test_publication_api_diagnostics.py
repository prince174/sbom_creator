"""API/CLI fixed publication facts, artifact blocking and post-analysis errors.

Only tiny runner/evaluator stubs run here; no scanner, project or network call.
"""
import json
import time

import pytest
from fastapi.testclient import TestClient

from sbom_creator import cli
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import AnalysisError
from sbom_creator.service import create_app

IMAGE = 'registry.example/app@sha256:' + 'a' * 64
HEADERS = {'Authorization': 'Bearer token'}
SETTINGS = Settings(registry_hosts=('registry.example',))
REFERENCE = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1}
SECRET = 'secret-marker-path-token-never-export'


def facts(committed):
    return {'publication_operation': 'cleanup_staging' if committed else 'commit_directory',
            'publication_error_code': 'PUBLICATION_PERMISSION_DENIED',
            'publication_os_error': 'windows_sharing_violation',
            'publication_committed': committed, 'diagnostics_status': 'complete'}


def terminal(client, path):
    for _ in range(100):
        state = client.get(path, headers=HEADERS).json()
        if state['status'] not in ('queued', 'running'):
            return state
        time.sleep(.01)
    pytest.fail('Stub analysis did not terminate')


@pytest.mark.parametrize('committed', [False, True])
def test_api_exports_fixed_publication_facts_and_blocks_failed_job_even_after_commit(
        tmp_path, monkeypatch, caplog, committed):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    caplog.set_level('INFO', logger='uvicorn.error')
    def runner(_url, _commit, _image, output, **_kwargs):
        if committed:
            output.mkdir()
            (output / 'final.cdx.json').write_text('{}')
        error = AnalysisError('reconcile_convert_validate', 'PermissionError', publication=facts(committed))
        error.args = (SECRET,)
        raise error
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={'image': IMAGE}, headers=HEADERS)
        assert response.status_code == 202
        path = response.json()['status_url']
        state = terminal(client, path)
        assert state['status'] == 'failed' and state['error'] == 'PermissionError'
        assert state['stage'] == 'reconcile_convert_validate'
        assert {key: state[key] for key in facts(committed)} == facts(committed)
        assert client.get(path + '/artifacts/final.cdx.json', headers=HEADERS).status_code == 409
        assert SECRET not in json.dumps(state) + caplog.text


class AttributePoison(PermissionError):
    @property
    def stage(self):
        raise AssertionError('External stage property must not be read')

    @property
    def error_type(self):
        raise AssertionError('External error_type property must not be read')

    @property
    def publication(self):
        raise AssertionError('External publication property must not be read')


@pytest.mark.parametrize('error', [RuntimeError(SECRET), AttributePoison(SECRET)])
def test_api_ignores_arbitrary_exception_attributes_and_does_not_mask_failure(
        tmp_path, monkeypatch, caplog, error):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    caplog.set_level('INFO', logger='uvicorn.error')
    if type(error) is RuntimeError:
        error.stage = SECRET
        error.error_type = SECRET
        error.publication = {'publication_operation': SECRET}
    def runner(*_args, **_kwargs):
        raise error
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={'image': IMAGE}, headers=HEADERS)
        state = terminal(client, response.json()['status_url'])
        assert state['status'] == 'failed' and state['stage'] == 'analysis'
        assert state['error'] in ('RuntimeError', 'Exception')
        assert not any(key.startswith('publication_') for key in state)
        assert SECRET not in json.dumps(state) + caplog.text


def test_api_verification_failure_keeps_its_actual_stage_and_blocks_predicted_artifacts(
        tmp_path, monkeypatch, caplog):
    monkeypatch.setenv('SBOM_API_TOKEN', 'token')
    caplog.set_level('INFO', logger='uvicorn.error')
    calls = []
    def runner(_url, _commit, _image, output, **_kwargs):
        output.mkdir()
        (output / 'final.cdx.json').write_text('{}')
        calls.append('prediction')
        return {'status': 'succeeded'}
    def compare(output, reference, scope):
        assert calls == ['prediction'] and (output / 'final.cdx.json').exists()
        assert reference == REFERENCE and scope == 'runtime'
        raise RuntimeError(SECRET)
    monkeypatch.setattr('sbom_creator.service.compare', compare)
    with TestClient(create_app(tmp_path, runner, SETTINGS)) as client:
        response = client.post('/v1/analyses', json={'image': IMAGE, 'run_mode': 'verification',
            'reference_scope': 'runtime', 'reference_sbom': REFERENCE}, headers=HEADERS)
        path = response.json()['status_url']
        state = terminal(client, path)
        assert state['status'] == 'failed' and state['stage'] == 'verification'
        assert state['error'] == 'RuntimeError'
        assert client.get(path + '/artifacts/final.cdx.json', headers=HEADERS).status_code == 409
        assert SECRET not in json.dumps(state) + caplog.text


@pytest.mark.parametrize('committed', [False, True])
def test_cli_exports_fixed_facts_without_message_path_or_false_unpublished_claim(
        tmp_path, monkeypatch, capsys, committed):
    def runner(*_args, **_kwargs):
        error = AnalysisError('reconcile_convert_validate', 'PermissionError', publication=facts(committed))
        error.args = (SECRET,)
        raise error
    monkeypatch.setattr(cli, 'analyze', runner)
    monkeypatch.setattr('sys.argv', ['sbom-creator', 'analyze', '--image', IMAGE,
                                  '--output', str(tmp_path / 'output')])
    assert cli.main() == 1
    captured = capsys.readouterr()
    state = json.loads(captured.err)
    assert not captured.out and state['status'] == 'failed'
    assert state['error_type'] == 'PermissionError' and state['stage'] == 'reconcile_convert_validate'
    assert {key: state[key] for key in facts(committed)} == facts(committed)
    assert SECRET not in captured.err and str(tmp_path) not in captured.err
    if committed:
        assert 'no final SBOM published' not in state.get('message', '')


def test_cli_never_reads_external_exception_stage_or_type_properties(tmp_path, monkeypatch, capsys):
    def runner(*_args, **_kwargs):
        raise AttributePoison(SECRET)
    monkeypatch.setattr(cli, 'analyze', runner)
    monkeypatch.setattr('sys.argv', ['sbom-creator', 'analyze', '--image', IMAGE,
                                  '--output', str(tmp_path / 'output')])
    assert cli.main() == 1
    captured = capsys.readouterr()
    state = json.loads(captured.err)
    assert state['stage'] == 'acquisition_or_configuration' and state['error_type'] == 'Exception'
    assert SECRET not in captured.err and not any(key.startswith('publication_') for key in state)


def test_cli_verification_failure_is_not_reported_as_acquisition_or_no_final(
        tmp_path, monkeypatch, capsys):
    reference = tmp_path / 'synthetic-reference.json'
    reference.write_text(json.dumps(REFERENCE))
    output = tmp_path / 'output'
    def runner(*_args, **_kwargs):
        output.mkdir()
        (output / 'final.cdx.json').write_text('{}')
        return {'status': 'succeeded'}
    def compare(*_args):
        assert (output / 'final.cdx.json').exists()
        raise ValueError(SECRET)
    monkeypatch.setattr(cli, 'analyze', runner)
    monkeypatch.setattr(cli, 'compare', compare)
    monkeypatch.setattr('sys.argv', ['sbom-creator', 'analyze', '--image', IMAGE, '--output', str(output),
        '--run-mode', 'verification', '--reference-sbom', str(reference), '--reference-scope', 'runtime'])
    assert cli.main() == 1
    captured = capsys.readouterr()
    state = json.loads(captured.err)
    assert state['stage'] == 'verification' and state['error_type'] == 'ValueError'
    assert SECRET not in captured.err and 'no final SBOM published' not in state.get('message', '')

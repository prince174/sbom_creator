import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    'local_api_client', Path(__file__).resolve().parents[1] / 'scripts/local_api_client.py')
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)

JOB = '11111111-1111-4111-8111-111111111111'
TOKEN = 'never-print-this-local-token'
IMAGE = 'registry.local/app@sha256:' + 'a' * 64


@pytest.fixture
def api(tmp_path):
    class State:
        status = 'succeeded'
        stage = 'image_scan'
        polls = 0
        redirect = None
        artifact_failure = None
        artifact_truncated = None
        body = None
        result = None

    state = State()
    state.requests = []
    state.artifacts = list(client.VIEWS)
    state.contents = {name: json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6',
        'components': [{'name': str(index)} for index in range(count)]}).encode()
        for name, count in zip(client.VIEWS, (2, 1, 3))}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, code, body, *, headers=None):
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Length', str(len(raw)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def record(self):
            state.requests.append((self.command, self.path))
            if self.headers['Authorization'] != 'Bearer ' + TOKEN:
                self.respond(401, {'message': TOKEN + ' private server authentication failure'})
                return False
            if state.redirect == self.path:
                self.respond(302, {'message': TOKEN}, headers={
                    'Location': server_url + '/stolen-token'})
                return False
            return True

        def do_POST(self):
            if not self.record():
                return
            state.body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.respond(202, {'id': JOB, 'status': 'queued',
                              'status_url': 'http://elsewhere.invalid/stolen-token'})

        def do_GET(self):
            if not self.record():
                return
            if self.path == '/v1/analyses/' + JOB:
                state.polls += 1
                self.respond(200, {'id': JOB, 'status': state.status,
                    'artifacts': state.artifacts, 'stage': state.stage,
                    'result': state.result,
                    'message': TOKEN + ' raw exception with C:/private/secret'})
                return
            name = self.path.rsplit('/', 1)[-1]
            if name == state.artifact_failure:
                self.respond(503, {'message': TOKEN + ' raw exception'})
            elif name == state.artifact_truncated:
                self.send_response(200)
                self.send_header('Content-Length', '200000')
                self.end_headers()
                self.wfile.write(b'{"partial":')
                self.close_connection = True
            else:
                self.respond(200, state.contents[name])

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server_url = f'http://127.0.0.1:{server.server_port}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token = tmp_path / 'token'
    token.write_text(TOKEN + '\n', encoding='utf-8')
    state.url, state.token = server_url, token
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run(api, tmp_path, **kwargs):
    return client.analyze(url=api.url, token_file=api.token, image=IMAGE,
                          output=tmp_path / 'result', poll_interval=0.001, **kwargs)


def test_real_mock_http_success_downloads_every_artifact_and_three_views(api, tmp_path):
    api.artifacts.append('coverage.json')
    api.contents['coverage.json'] = b'{"partial":true}'
    progress = []
    report = run(api, tmp_path, progress=progress.append)
    assert report['status'] == 'succeeded'
    assert report['counts'] == {'final.cdx.json': 2, 'os.cdx.json': 1, 'full.cdx.json': 3}
    assert progress == [{'job_id': JOB, 'status': 'accepted'}]
    assert api.body == {'image': IMAGE, 'run_mode': 'production'}
    assert len([item for item in api.requests if item[0] == 'POST']) == 1
    assert len(report['downloaded_artifacts']) == 4
    assert all(len(item['sha256']) == 64 for item in report['downloaded_artifacts'])
    assert json.loads((tmp_path / 'result/client-report.json').read_bytes()) == report
    assert all('stolen-token' not in path for _, path in api.requests)
    assert TOKEN not in json.dumps(report)


def test_cli_prints_only_safe_job_counts_and_never_token(api, tmp_path, capsys):
    assert client.main(['--url', api.url, '--token-file', str(api.token), 'analyze',
                        '--image', IMAGE, '--output', str(tmp_path / 'result')]) == 0
    printed = capsys.readouterr().out
    lines = [json.loads(value) for value in printed.splitlines()]
    assert lines[0]['job_id'] == JOB
    assert lines[-1]['status'] == 'succeeded'
    assert TOKEN not in printed and IMAGE not in printed


@pytest.mark.parametrize('contents,code', [(b'', 'TOKEN_INVALID'),
    (b'x' * 8193, 'TOKEN_INVALID'), (b'abc\ndef', 'TOKEN_INVALID'),
    (b'\xff', 'TOKEN_UNAVAILABLE')])
def test_invalid_token_never_sends_request_or_creates_output(api, tmp_path, contents, code):
    api.token.write_bytes(contents)
    with pytest.raises(client.ClientError, match=code):
        run(api, tmp_path)
    assert not api.requests and not (tmp_path / 'result').exists()


def test_missing_token_is_redacted(tmp_path):
    with pytest.raises(client.ClientError) as caught:
        client.read_token(tmp_path / 'private-token-name')
    assert caught.value.fields() == {'code': 'TOKEN_UNAVAILABLE'}
    assert 'private-token-name' not in str(caught.value)


def test_wrong_token_reports_only_fixed_http_code(api, tmp_path):
    api.token.write_text('wrong-token', encoding='utf-8')
    report = run(api, tmp_path)
    assert report['error'] == {'code': 'HTTP_ERROR', 'http_status': 401}
    assert TOKEN not in json.dumps(report) and 'wrong-token' not in json.dumps(report)


@pytest.mark.parametrize('url', ['http://foreign.invalid', 'http://user:secret@localhost',
    'http://localhost/path', 'http://localhost/?token=secret', 'http://localhost/#secret',
    'file:///tmp/token', 'http://localhost:99999', 'http://localhost\n'])
def test_unsafe_base_url_is_rejected_before_token_or_network(tmp_path, url):
    with pytest.raises(client.ClientError, match='INVALID_BASE_URL'):
        client.analyze(url=url, token_file='absent', image=IMAGE, output=tmp_path / 'result')
    assert not (tmp_path / 'result').exists()


def test_existing_output_never_overwritten(api, tmp_path):
    result = tmp_path / 'result'
    result.mkdir()
    sentinel = result / 'client-report.json'
    sentinel.write_bytes(b'keep me')
    with pytest.raises(client.ClientError, match='OUTPUT_EXISTS'):
        run(api, tmp_path)
    assert sentinel.read_bytes() == b'keep me'
    assert not api.requests


@pytest.mark.parametrize('path', ['/v1/analyses', '/v1/analyses/' + JOB,
                                 '/v1/analyses/' + JOB + '/artifacts/final.cdx.json'])
def test_redirects_are_not_followed_and_authorization_is_not_forwarded(api, tmp_path, path):
    api.redirect = path
    report = run(api, tmp_path)
    assert report['status'] == 'failed'
    assert report['error'] == {'code': 'HTTP_ERROR', 'http_status': 302}
    assert all('stolen-token' not in item[1] for item in api.requests)
    assert TOKEN not in (tmp_path / 'result/client-report.json').read_text()


@pytest.mark.parametrize('stage,expected', [('image_scan', {'stage': 'image_scan'}),
    ('private-path-' + TOKEN, {}), ({'secret': TOKEN}, {})])
def test_failed_job_does_not_download_and_only_fixed_stage_is_exposed(api, tmp_path, stage, expected):
    api.status, api.stage = 'failed', stage
    report = run(api, tmp_path)
    assert report['error'] == {'code': 'JOB_FAILED', **expected}
    assert not report['downloaded_artifacts']
    assert all('/artifacts/' not in path for _, path in api.requests)
    assert TOKEN not in json.dumps(report)


@pytest.mark.parametrize('bad', ['../outside.json', '/absolute.json', '..\\outside.json',
    'http://evil.invalid/a.json', 'client-report.json', 'final.cdx.json', 'a..json',
    'con.json', 'lpt1.json'])
def test_artifact_names_are_validated_before_any_download(api, tmp_path, bad):
    api.artifacts.append(bad)
    report = run(api, tmp_path)
    assert report['error'] == {'code': 'INVALID_ARTIFACT_LIST'}
    assert all('/artifacts/' not in path for _, path in api.requests)
    assert not (tmp_path / 'outside.json').exists()


def test_success_without_all_three_views_is_invalid(api, tmp_path):
    api.artifacts = ['final.cdx.json']
    assert run(api, tmp_path)['error'] == {'code': 'INVALID_ARTIFACT_LIST'}


def test_partial_downloads_preserved_with_failure_report(api, tmp_path):
    api.artifact_failure = 'os.cdx.json'
    report = run(api, tmp_path)
    assert report['error'] == {'code': 'HTTP_ERROR', 'http_status': 503}
    assert [item['name'] for item in report['downloaded_artifacts']] == ['final.cdx.json']
    assert report['partial_artifact'] == 'os.cdx.json'
    assert (tmp_path / 'result/final.cdx.json').read_bytes() == api.contents['final.cdx.json']
    assert json.loads((tmp_path / 'result/client-report.json').read_bytes()) == report


def test_truncated_http_body_is_failure_and_preserves_first_artifact(api, tmp_path):
    api.artifact_truncated = 'os.cdx.json'
    report = run(api, tmp_path)
    assert report['status'] == 'failed'
    assert report['error']['code'] in ('TRANSFER_OR_OUTPUT_FAILED', 'INCOMPLETE_DOWNLOAD')
    assert report['downloaded_artifacts'][0]['name'] == 'final.cdx.json'
    assert (tmp_path / 'result/client-report.json').is_file()


def test_poll_deadline_does_not_resubmit(api, tmp_path):
    api.status = 'running'
    report = run(api, tmp_path, timeout=0.05)
    assert report['error'] == {'code': 'TIMEOUT'}
    assert len([item for item in api.requests if item[0] == 'POST']) == 1


def test_artifact_download_budget_preserves_partial_and_report(api, tmp_path, monkeypatch):
    monkeypatch.setattr(client, 'MAX_ARTIFACT_BYTES', 10)
    report = run(api, tmp_path)
    assert report['error'] == {'code': 'ARTIFACT_TOO_LARGE'}
    assert report['partial_artifact'] == 'final.cdx.json'
    assert not report['downloaded_artifacts']


def test_failed_cli_never_exposes_http_response_message(api, tmp_path, capsys):
    api.artifact_failure = 'final.cdx.json'
    assert client.main(['--url', api.url, '--token-file', str(api.token), 'analyze',
                        '--image', IMAGE, '--output', str(tmp_path / 'result')]) == 1
    output = capsys.readouterr().out
    assert TOKEN not in output and 'raw exception' not in output
    assert json.loads(output.splitlines()[-1])['error']['http_status'] == 503


@pytest.mark.parametrize('result,expected', [({'partial': True}, True),
    ({'partial': False}, False), ({'partial': 'yes-' + TOKEN}, None),
    ({'partial': 1}, None), ({}, None), (None, None), (['partial', TOKEN], None)])
def test_succeeded_partial_is_exact_boolean_warning_in_report_and_stdout(
        api, tmp_path, capsys, result, expected):
    api.result = result
    assert client.main(['--url', api.url, '--token-file', str(api.token), 'analyze',
                        '--image', IMAGE, '--output', str(tmp_path / 'result')]) == 0
    printed = capsys.readouterr().out
    summary = json.loads(printed.splitlines()[-1])
    report = json.loads((tmp_path / 'result/client-report.json').read_bytes())
    assert summary['partial'] is expected and report['partial'] is expected
    assert summary['status'] == report['status'] == 'succeeded'
    assert len(report['downloaded_artifacts']) == 3
    assert TOKEN not in printed and TOKEN not in json.dumps(report)

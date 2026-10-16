"""Image-only local API client. Credentials are read from a file, never printed.

Example: python scripts/local_api_client.py analyze --image REGISTRY/APP@sha256:DIGEST
         --output workspace/my-analysis
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import re
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = 'http://127.0.0.1:18082'
DEFAULT_TOKEN = ROOT / 'secrets/local-mvp/api-token'
MAX_JSON_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_VIEW_BYTES = 64 * 1024 * 1024
VIEWS = ('final.cdx.json', 'os.cdx.json', 'full.cdx.json')
RESERVED_NAMES = frozenset({'con', 'prn', 'aux', 'nul',
    *(f'com{number}' for number in range(1, 10)),
    *(f'lpt{number}' for number in range(1, 10))})
STAGES = frozenset({'configuration', 'assessment_configuration', 'source_inspection',
    'source_scan', 'java_source_dependencies', 'image_scan', 'publication', 'input_validation',
    'checkout', 'reconcile_convert_validate', 'verification', 'analysis',
    'acquisition_or_configuration'})


class ClientError(Exception):
    """Only fixed local codes, bounded HTTP status and approved stages cross the UI."""
    def __init__(self, code, *, http_status=None, stage=None):
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.stage = stage

    def fields(self):
        result = {'code': self.code}
        if type(self.http_status) is int and 100 <= self.http_status <= 599:
            result['http_status'] = self.http_status
        if type(self.stage) is str and self.stage in STAGES:
            result['stage'] = self.stage
        return result


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def base_url(value):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in ('http', 'https') and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
                 and not any(ord(char) < 33 or ord(char) == 127 for char in value)
                 and '\\' not in value and len(value) <= 2048)
        if parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1', 'localhost', '::1'):
            valid = False
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            valid = False
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ClientError('INVALID_BASE_URL')
    return value.rstrip('/')


def read_token(path):
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(8193)
        token = raw.decode('utf-8').strip()
    except (OSError, UnicodeError):
        raise ClientError('TOKEN_UNAVAILABLE') from None
    if (len(raw) > 8192 or not token
            or any(ord(char) < 33 or ord(char) > 126 for char in token)):
        raise ClientError('TOKEN_INVALID')
    return token


def artifact_names(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise ClientError('INVALID_ARTIFACT_LIST')
    for name in values:
        if (type(name) is not str or not re.fullmatch(r'[a-z][a-z0-9.-]{0,79}\.json', name)
                or '..' in name or name == 'client-report.json'
                or name.split('.', 1)[0] in RESERVED_NAMES):
            raise ClientError('INVALID_ARTIFACT_LIST')
    if len(set(values)) != len(values) or not set(VIEWS) <= set(values):
        raise ClientError('INVALID_ARTIFACT_LIST')
    return values


class Session:
    def __init__(self, url, token, timeout):
        self.url, self.token = url, token
        self.deadline = time.monotonic() + timeout
        # Ignore ambient proxies; never forward a local bearer token through one.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise ClientError('TIMEOUT')
        return value

    def open(self, path, payload=None):
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'}
        body = None
        if payload is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(self.url + path, headers=headers, data=body)
        try:
            return self.opener.open(request, timeout=min(10, self.remaining()))
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            raise ClientError('HTTP_ERROR', http_status=code) from None
        except (OSError, ValueError, urllib.error.URLError):
            raise ClientError('CONNECTION_FAILED') from None

    def json(self, path, *, payload=None, expected=200):
        try:
            with self.open(path, payload) as response:
                if response.status != expected:
                    raise ClientError('UNEXPECTED_HTTP_STATUS', http_status=response.status)
                raw = response.read(MAX_JSON_BYTES + 1)
                self.remaining()
            if len(raw) > MAX_JSON_BYTES:
                raise ClientError('RESPONSE_TOO_LARGE')
            result = json.loads(raw)
        except (UnicodeError, ValueError, RecursionError):
            raise ClientError('INVALID_RESPONSE') from None
        except (OSError, http.client.HTTPException):
            raise ClientError('CONNECTION_FAILED') from None
        if not isinstance(result, dict):
            raise ClientError('INVALID_RESPONSE')
        return result


def view_counts(output):
    counts = {}
    try:
        for name in VIEWS:
            path = output / name
            if path.stat().st_size > MAX_VIEW_BYTES:
                raise ClientError('VIEW_TOO_LARGE')
            document = json.loads(path.read_bytes())
            if (not isinstance(document, dict) or document.get('bomFormat') != 'CycloneDX'
                    or document.get('specVersion') not in ('1.6', '1.7')
                    or not isinstance(document.get('components', []), list)):
                raise ClientError('INVALID_SBOM_VIEW')
            counts[name] = len(document.get('components', []))
    except (ValueError, UnicodeError, RecursionError):
        raise ClientError('INVALID_SBOM_VIEW') from None
    return counts


def analyze(*, url=DEFAULT_URL, token_file=DEFAULT_TOKEN, image, output,
            timeout=1200, poll_interval=1, progress=None):
    """Submit once, poll within one deadline, preserve all owned output on failure."""
    url = base_url(url)
    if (not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0
            or not isinstance(poll_interval, (int, float)) or not math.isfinite(poll_interval)
            or poll_interval <= 0):
        raise ClientError('INVALID_TIMEOUT')
    if (type(image) is not str or not image or len(image) > 2048
            or any(ord(char) < 33 or ord(char) == 127 for char in image)):
        raise ClientError('INVALID_IMAGE')
    token = read_token(token_file)
    output = Path(output)
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise ClientError('OUTPUT_EXISTS') from None
    except OSError:
        raise ClientError('OUTPUT_IO_ERROR') from None
    report = {'status': 'failed', 'submitted_once': False, 'downloaded_artifacts': [],
              'counts': {}, 'partial_artifact': None, 'partial': None}
    started = time.monotonic()
    session = Session(url, token, timeout)
    try:
        report['submitted_once'] = True
        accepted = session.json('/v1/analyses', payload={'image': image,
            'run_mode': 'production'}, expected=202)
        job_id = accepted.get('id')
        try:
            if type(job_id) is not str or str(uuid.UUID(job_id)) != job_id:
                raise ValueError()
        except (ValueError, AttributeError):
            raise ClientError('INVALID_JOB_ID') from None
        report.update(job_id=job_id, submitted_once=True)
        if progress is not None:
            progress({'job_id': job_id, 'status': 'accepted'})
        status_path = '/v1/analyses/' + job_id  # Ignore any server-provided URL.
        while True:
            state = session.json(status_path)
            if state.get('id') != job_id:
                raise ClientError('INVALID_RESPONSE')
            status = state.get('status')
            if status == 'failed':
                raise ClientError('JOB_FAILED', stage=state.get('stage'))
            if status == 'succeeded':
                names = artifact_names(state.get('artifacts'))
                result = state.get('result')
                partial = result.get('partial') if type(result) is dict else None
                report['partial'] = partial if type(partial) is bool else None
                break
            if status not in ('queued', 'running'):
                raise ClientError('INVALID_JOB_STATUS')
            time.sleep(min(poll_interval, session.remaining()))
        total = 0
        for name in names:
            report['partial_artifact'] = name
            checksum, size = hashlib.sha256(), 0
            with session.open(status_path + '/artifacts/' + name) as response:
                if response.status != 200:
                    raise ClientError('UNEXPECTED_HTTP_STATUS', http_status=response.status)
                length = response.headers.get('Content-Length')
                if length is not None and (not re.fullmatch(r'[0-9]{1,20}', length)
                        or int(length) > MAX_ARTIFACT_BYTES):
                    raise ClientError('ARTIFACT_TOO_LARGE')
                with (output / name).open('xb') as stream:
                    while chunk := response.read(128 * 1024):
                        session.remaining()
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_ARTIFACT_BYTES or total > MAX_TOTAL_BYTES:
                            raise ClientError('ARTIFACT_TOO_LARGE')
                        stream.write(chunk)
                        checksum.update(chunk)
                if length is not None and size != int(length):
                    raise ClientError('INCOMPLETE_DOWNLOAD')
            report['downloaded_artifacts'].append({'name': name, 'bytes': size,
                                                   'sha256': checksum.hexdigest()})
            report['partial_artifact'] = None
        report.update(status='succeeded', counts=view_counts(output))
    except ClientError as error:
        report['error'] = error.fields()
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        report['error'] = {'code': 'TRANSFER_OR_OUTPUT_FAILED'}
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        try:
            with (output / 'client-report.json').open('x', encoding='utf-8') as stream:
                json.dump(report, stream, ensure_ascii=True, indent=2)
                stream.write('\n')
        except OSError:
            raise ClientError('REPORT_WRITE_FAILED') from None
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default=DEFAULT_URL)
    parser.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('analyze', help='Submit one image-only production analysis')
    command.add_argument('--image', required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--timeout', type=float, default=1200)
    args = parser.parse_args(argv)
    try:
        report = analyze(url=args.url, token_file=args.token_file, image=args.image,
            output=args.output, timeout=args.timeout,
            progress=lambda value: print(json.dumps(value), flush=True))
    except ClientError as error:
        print(json.dumps({'status': 'failed', 'error': error.fields()}), flush=True)
        return 1
    fields = {key: report[key] for key in ('status', 'counts', 'partial', 'elapsed_seconds')}
    if 'job_id' in report:
        fields['job_id'] = report['job_id']
    if 'error' in report:
        fields['error'] = report['error']
    fields['downloaded_artifact_count'] = len(report['downloaded_artifacts'])
    print(json.dumps(fields), flush=True)
    return 0 if report['status'] == 'succeeded' else 1


if __name__ == '__main__':
    raise SystemExit(main())

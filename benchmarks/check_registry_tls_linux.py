"""Run INSIDE the isolated external Linux harness, never in deployed services.

Input image is mounted read-only; fixture listens only on container loopback.
The container has no external network, project source, oracle or Docker socket.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import ssl
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

from registry_fixture import Fixture, archive_config, digest


def failure_kind(code, error):
    if code == 0:
        return 'SUCCESS'
    text = error.decode('utf-8', errors='replace').lower()
    if 'x509:' in text and ('unknown authority' in text or 'certificate' in text):
        return 'TLS_CERTIFICATE_REJECTED'
    if '401' in text or 'unauthorized' in text:
        return 'AUTH_UNAUTHORIZED'
    return 'UNCLASSIFIED_FAILURE'


def invoke(arguments, environment):
    started = time.monotonic()
    result = subprocess.run(['/tools/crane', *arguments], env=environment,
                            capture_output=True, timeout=30, check=False)
    if len(result.stdout) + len(result.stderr) > 1024 * 1024:
        raise ValueError('Crane diagnostic budget exceeded')
    return result, time.monotonic() - started


def main():
    work = Path('/work')
    report_path = work / 'report.json'
    if report_path.exists():
        raise FileExistsError('Preserve completed run')
    assert os.getuid() != 0
    assert shutil.which('docker') is None
    assert not Path('/var/run/docker.sock').exists()
    caps = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                if line.startswith('CapEff:'))
    assert int(caps, 16) == 0
    fixture = Fixture('/input/image.tar')
    auth = base64.b64encode(('fixture:' + secrets.token_urlsafe(32)).encode()).decode()
    fixture.authorization = 'Basic ' + auth
    server = ThreadingHTTPServer(('127.0.0.1', 0), fixture.handler())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/inputca/fixture.crt', '/inputca/fixture.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host = f'127.0.0.1:{server.server_port}'
    reference = f'{host}/fixture@{fixture.manifest["digest"]}'
    home = work / 'home'
    empty = work / 'empty'
    wrong = work / 'wrong'
    for directory in (home, empty, wrong):
        directory.mkdir(exist_ok=False)
    (home / 'config.json').write_text(json.dumps({'auths': {host: {'auth': auth}}}))
    (wrong / 'config.json').write_text(json.dumps({'auths': {host: {
        'auth': base64.b64encode(b'fixture:intentionally-wrong').decode()}}}))
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home),
                   'DOCKER_CONFIG': str(home), 'SSL_CERT_FILE': '/inputca/fixture.crt',
                   'SSL_CERT_DIR': str(empty)}
    report = {'status': 'STARTED', 'runtime_changed': False, 'docker_inside_harness': False,
              'project_executed': False, 'oracle_available': False, 'tls_insecure_flag': False,
              'uid': os.getuid(), 'capabilities_effective': caps, 'checks': {},
              'manifest_digest': fixture.manifest['digest'], 'config_digest': fixture.config,
              'crane_binary_sha256': hashlib.sha256(Path('/tools/crane').read_bytes()).hexdigest()}
    try:
        positive, seconds = invoke(['manifest', reference], environment)
        if positive.returncode or digest(positive.stdout.rstrip(b'\n')) != fixture.manifest['digest']:
            raise AssertionError('Trusted TLS/auth positive control failed; negatives not scored')
        report['checks']['trusted_tls_correct_credentials'] = 'SUCCESS'
        report['manifest_seconds'] = seconds
        for name in ('untrusted_ca', 'missing_credentials', 'wrong_password'):
            probe = dict(environment)
            expected = 'AUTH_UNAUTHORIZED'
            if name == 'untrusted_ca':
                probe['SSL_CERT_FILE'] = str(empty / 'missing.crt')
                expected = 'TLS_CERTIFICATE_REJECTED'
            else:
                probe['HOME'] = probe['DOCKER_CONFIG'] = str(empty if name == 'missing_credentials' else wrong)
            result, _ = invoke(['manifest', reference], probe)
            observed = failure_kind(result.returncode, result.stderr)
            report['checks'][name] = observed
            if observed != expected:
                raise AssertionError('Negative control had unexpected class: ' + name)
        acquired = work / 'acquired.tar'
        result, seconds = invoke(['pull', reference, str(acquired), '--format=tarball',
                                  '--platform=linux/amd64'], environment)
        if result.returncode:
            raise AssertionError('Trusted TLS/auth image pull failed')
        config, layers = archive_config(acquired)
        assert config == fixture.config
        report.update(status='PASSED', pull_seconds=seconds,
                      archive_bytes=acquired.stat().st_size, config_digest_verified=True,
                      diff_ids=layers, requests=len(fixture.requests),
                      limitations=['External transport test, not runtime integration',
                                   'No redirect/credential-helper adversarial tests',
                                   'No component/direct accuracy change or independent control',
                                   'Output cap checked after subprocess, container disk quota not tested'])
    except Exception as error:
        report.update(status='FAILED', failure_type=type(error).__name__,
                      failure=str(error) if isinstance(error, AssertionError) else 'Redacted harness failure')
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        # Credential files are ephemeral; do not retain even the synthetic password.
        for directory in (home, wrong):
            (directory / 'config.json').unlink(missing_ok=True)
    print(json.dumps({'status': report['status'], 'checks': report['checks']}))


if __name__ == '__main__':
    main()

"""Authenticated TLS loopback fixture; generated credentials never enter reports."""
import base64
import json
import os
import secrets
import tempfile
import time
from pathlib import Path

from check_go_registry_identity import scan
from http_integration import command, free_port
from run import ROOT, atomic_json


def main():
    port = free_port()
    authority = f'localhost:{port}'
    target = authority + '/fixture/hey:tls'
    password = secrets.token_urlsafe(32)
    env = dict(os.environ, FIXTURE_PASSWORD=password)
    helper = command(['docker', 'image', 'inspect', 'sbom-creator:0.5.0', '--format', '{{.Id}}'])
    hashed = command(['docker', 'run', '--rm', '--network=none', '-e', 'FIXTURE_PASSWORD', helper,
                      'python', '-c', 'import crypt,os; print(crypt.crypt(os.environ["FIXTURE_PASSWORD"],crypt.mksalt(crypt.METHOD_BLOWFISH)))'], env=env)
    registry = command(['docker', 'image', 'inspect', 'registry:2.8.3', '--format', '{{.Id}}'])
    with tempfile.TemporaryDirectory(prefix='sbom-r50-') as folder:
        work = Path(folder)
        command(['C:/Program Files/Git/usr/bin/openssl.exe', 'req', '-x509', '-newkey', 'rsa:2048',
                 '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext',
                 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(work / 'key.pem'),
                 '-out', str(work / 'ca.crt')])
        (work / 'htpasswd').write_text('fixture:' + hashed + '\n', encoding='utf-8')
        client = work / 'client'
        client.mkdir()
        (client / 'config.json').write_text(json.dumps({'auths': {authority: {
            'auth': base64.b64encode(('fixture:' + password).encode()).decode()}}}), encoding='utf-8')
        container = command(['docker', 'run', '-d', '--name', 'sbom-r50-' + secrets.token_hex(6),
            '--memory=256m', '--cpus=1', '-p', f'127.0.0.1:{port}:5000',
            '--mount', f'type=bind,source={work},target=/fixture,readonly',
            '-e', 'REGISTRY_HTTP_TLS_CERTIFICATE=/fixture/ca.crt',
            '-e', 'REGISTRY_HTTP_TLS_KEY=/fixture/key.pem', '-e', 'REGISTRY_AUTH=htpasswd',
            '-e', 'REGISTRY_AUTH_HTPASSWD_REALM=fixture',
            '-e', 'REGISTRY_AUTH_HTPASSWD_PATH=/fixture/htpasswd', registry])
        try:
            time.sleep(2)
            image = (ROOT / 'benchmarks/.work/paired-hey-v1/runtime.id').read_text().strip()
            command(['docker', 'tag', image, target])
            command(['docker', 'push', target], env=dict(os.environ, DOCKER_CONFIG=str(client)), timeout=180)
            ca = work / 'ca.crt'
            identity, payload_sha = scan(target, ca=ca, password=password)
            negatives = {}
            for name, options in [('missing_credentials', {'ca': ca}),
                                  ('wrong_password', {'ca': ca, 'password': 'invalid-fixture'}),
                                  ('wrong_authority', {'ca': ca, 'password': password,
                                                       'auth_authority': 'localhost:1'})]:
                try:
                    scan(target, **options)
                except RuntimeError:
                    negatives[name] = 'rejected'
                else:
                    raise AssertionError(name + ' accepted')
            # Supply a different valid certificate, never skip certificate verification.
            command(['C:/Program Files/Git/usr/bin/openssl.exe', 'req', '-x509', '-newkey', 'rsa:2048',
                     '-nodes', '-days', '1', '-subj', '/CN=unrelated', '-keyout', str(work / 'other.key'),
                     '-out', str(work / 'other.crt')])
            try:
                scan(target, ca=work / 'other.crt', password=password)
            except RuntimeError:
                negatives['untrusted_ca'] = 'rejected'
            else:
                raise AssertionError('Untrusted CA accepted')
            report = {'experiment': 'R50', 'registry_image_id': registry, 'hash_helper_image_id': helper,
                      'image_config_digest': identity['image_config_digest'], 'payload_sha256': payload_sha,
                      'authenticated_tls_read': True, 'negative_checks': negatives,
                      'runtime_changed': False, 'direct_accuracy': None}
            encoded = json.dumps(report)
            if password in encoded or hashed in encoded:
                raise AssertionError('Fixture secret leaked into report')
            atomic_json(ROOT / 'docs/go-registry-auth-v1.json', report)
            print('R50 passed: TLS authenticated payload and four rejection cases')
        finally:
            command(['docker', 'rm', '-f', container])


if __name__ == '__main__':
    main()

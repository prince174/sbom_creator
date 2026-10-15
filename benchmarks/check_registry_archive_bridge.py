"""External loopback registry experiment; no Docker or oracle used by predictor.

HTTP/--insecure is restricted to this ephemeral loopback fixture. Optional TLS
probe requires a platform-specific trusted fixture CA. This is not a production
transport adapter; Windows Go trust does not use Unix SSL_CERT_FILE overrides.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import shutil
import ssl
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from check_jar_content_budget import BudgetFiles
from run import ROOT, atomic_json

from sbom_creator import payload, scanner
from sbom_creator.acquire import Settings, clean_environment, run_command
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def archive_config(archive_path):
    """Bind Docker-compatible acquired tarball to config bytes and diff IDs."""
    with tarfile.open(archive_path) as archive:
        def read(name):
            member = archive.getmember(name)
            if not member.isfile() or member.size > 4 * 1024 * 1024:
                raise ValueError('Invalid image metadata')
            return archive.extractfile(member).read(member.size + 1)
        manifests = json.loads(read('manifest.json'))
        if len(manifests) != 1:
            raise ValueError('Ambiguous image manifest')
        manifest = manifests[0]
        raw = read(manifest['Config'])
        config = json.loads(raw)
        if (config.get('os'), config.get('architecture')) != ('linux', 'amd64'):
            raise ValueError('Wrong image platform')
        if len(manifest['Layers']) != len(config['rootfs']['diff_ids']):
            raise ValueError('Inconsistent layer count')
        return digest(raw), config['rootfs']['diff_ids']


class Fixture:
    """Only serve content-addressed blobs from the existing paired OCI archive."""
    def __init__(self, source):
        self.source = source
        self.requests = []
        self.authorization = None
        with tarfile.open(source) as archive:
            index = json.load(archive.extractfile('index.json'))['manifests'][0]
            raw = archive.extractfile('blobs/sha256/' + index['digest'][7:]).read()
            assert digest(raw) == index['digest']
            candidates = [entry for entry in json.loads(raw)['manifests']
                          if entry.get('platform', {}).get('os') == 'linux'
                          and entry.get('platform', {}).get('architecture') == 'amd64']
            if len(candidates) != 1:
                raise ValueError('Ambiguous fixture platform')
            self.manifest = candidates[0]
            raw = archive.extractfile('blobs/sha256/' + self.manifest['digest'][7:]).read()
            assert digest(raw) == self.manifest['digest']
            self.config = json.loads(raw)['config']['digest']

    def handler(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_HEAD(self):
                self.respond(False)

            def do_GET(self):
                self.respond(True)

            def respond(self, body):
                fixture.requests.append(self.path)
                if fixture.authorization and self.headers.get('Authorization') != fixture.authorization:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="fixture"')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if self.path == '/v2/':
                    self.send_response(200)
                    self.send_header('Content-Length', '2')
                    self.end_headers()
                    if body:
                        self.wfile.write(b'{}')
                    return
                match = re.fullmatch(r'/v2/fixture/(manifests|blobs)/(sha256:[a-f0-9]{64})', self.path)
                if not match:
                    self.send_error(404)
                    return
                name = 'blobs/sha256/' + match[2][7:]
                with tarfile.open(fixture.source) as archive:
                    try:
                        member = archive.getmember(name)
                    except KeyError:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header('Docker-Content-Digest', match[2])
                    self.send_header('Content-Length', str(member.size))
                    self.send_header('Content-Type', fixture.manifest['mediaType']
                                     if match[1] == 'manifests' else 'application/octet-stream')
                    self.end_headers()
                    if body:
                        with archive.extractfile(member) as stream:
                            shutil.copyfileobj(stream, self.wfile, 128 * 1024)
        return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tls-fixture', action='store_true', help='Probe explicit fixture CA (Windows currently rejects it)')
    parser.add_argument('--run-id', default=None, help='Fresh namespace for a changed hypothesis')
    parser.add_argument('--openssl', default='C:/Program Files/Git/usr/bin/openssl.exe')
    args = parser.parse_args()
    http_fixture = not args.tls_fixture
    namespace = args.run_id or ('registry-archive-bridge-v1' if http_fixture else 'registry-archive-bridge-v2')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,70}', namespace):
        raise ValueError('Invalid run ID')
    work = ROOT / 'benchmarks/.work' / namespace
    output = ROOT / 'benchmarks/results' / namespace
    if work.exists() or output.exists():
        raise FileExistsError('Preserve attempted experiment; use a reviewed new namespace')
    work.mkdir()
    crane_dir = ROOT / 'benchmarks/.work/crane-r94'
    provenance = json.loads((crane_dir / 'provenance.json').read_bytes())
    crane = crane_dir / 'crane.exe'
    assert hashlib.sha256(crane.read_bytes()).hexdigest() == provenance['binary_sha256']
    fixture = Fixture(ROOT / 'benchmarks/.work/paired-javalin-reactor-v1/image.tar')
    environment = clean_environment()
    for key in list(environment):
        if 'PROXY' in key.upper():
            del environment[key]
    home = work / 'empty-home'
    home.mkdir()
    environment.update(HOME=str(home), USERPROFILE=str(home), DOCKER_CONFIG=str(home))
    server = ThreadingHTTPServer(('127.0.0.1', 0), fixture.handler())
    negative = {}
    if not http_fixture:
        run_command([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                     '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
                     '-keyout', str(work / 'fixture.key'), '-out', str(work / 'fixture.crt')],
                    cwd=work, env=environment, timeout=30, max_output_bytes=1024 * 1024,
                    label='Fixture certificate')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work / 'fixture.crt', work / 'fixture.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        auth = base64.b64encode(('fixture:' + secrets.token_urlsafe(32)).encode()).decode()
        fixture.authorization = 'Basic ' + auth
        (home / 'config.json').write_text(json.dumps({'auths': {
            f'127.0.0.1:{server.server_port}': {'auth': auth}}}), encoding='utf-8')
        environment['SSL_CERT_FILE'] = str(work / 'fixture.crt')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    acquired = work / 'acquired.tar'
    reference = f'127.0.0.1:{server.server_port}/fixture@{fixture.manifest["digest"]}'
    started = time.monotonic()
    try:
        if not http_fixture:
            for kind in ('untrusted_ca', 'missing_credentials'):
                probe_env = dict(environment)
                if kind == 'untrusted_ca':
                    probe_env['SSL_CERT_FILE'] = str(work / 'nonexistent-ca.crt')
                    probe_env['SSL_CERT_DIR'] = str(work / 'nonexistent-ca-dir')
                else:
                    empty = work / 'no-credentials'
                    empty.mkdir()
                    probe_env.update(HOME=str(empty), USERPROFILE=str(empty), DOCKER_CONFIG=str(empty))
                try:
                    run_command([str(crane), 'manifest', reference], cwd=work, env=probe_env,
                                timeout=20, max_output_bytes=1024 * 1024,
                                label='Negative registry probe')
                except RuntimeError:
                    negative[kind] = 'COMMAND_FAILED_NOT_YET_ATTRIBUTED'
                else:
                    raise AssertionError('Unsafe registry probe accepted: ' + kind)
        command = [str(crane), 'pull', reference, str(acquired), '--format=tarball',
                   '--platform=linux/amd64']
        if http_fixture:
            command.append('--insecure')
        run_command(command, cwd=work, env=environment,
                    timeout=120, max_output_bytes=1024 * 1024, label='Loopback crane pull',
                    monitored_paths=((work, Settings().max_archive_bytes),))
    except RuntimeError as error:
        atomic_json(output / 'report.json', {
            'status': 'ACQUISITION_FAILED', 'runtime_changed': False, 'tool': provenance,
            'stage': 'registry_pull', 'reason': str(error), 'fixture_tls': not http_fixture,
            'negative_transport_checks': negative, 'http_requests': fixture.requests,
            'three_views_published': False, 'accuracy': None,
            'limitation': 'Do not interpret failed probes as authentication checks until trusted TLS succeeds. No host trust-store modifications.'})
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    pull_seconds = time.monotonic() - started
    config, layers = archive_config(acquired)
    assert config == fixture.config
    stats = {'read_bytes': 0, 'read_calls': 0, 'budget_rejections': 0}
    original_collect = payload.collect

    def collect(document):
        with patch.object(payload, 'ImageFiles', BudgetFiles):
            return original_collect(document, acquired)

    config_text = scanner.IMAGE_CONFIG
    for suffix in ('jar', 'war', 'ear', 'zip', 'hpi', 'jpi', 'nar', 'jmod'):
        config_text = config_text.replace('      - "**/*.' + suffix + '"\n', '')
    analysis = work / 'analysis'
    started = time.monotonic()
    with patch.object(BudgetFiles, 'stats', stats), patch.object(scanner, 'IMAGE_CONFIG', config_text), patch.object(scanner, 'collect_payload', collect):
        analyze_local(ROOT / 'benchmarks/.work/paired-javalin-reactor-v1/src', reference,
                      analysis, Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'),
                                         registry_hosts=(reference.split('/')[0],),
                                         image_archive=str(acquired)))
    analysis_seconds = time.monotonic() - started
    coordinates = {}
    for view in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis / (view + '.cdx.json')).read_bytes()))
        current = json.loads((analysis / (view + '.cdx.json')).read_bytes())
        old_path = ROOT / 'benchmarks/.work/paired-javalin-reactor-v1/analysis-metadata-archive-v1' / (view + '.cdx.json')
        previous = json.loads(old_path.read_bytes())
        def identities(document):
            return sorted((c.get('purl', ''), c.get('name', ''), c.get('version', ''))
                          for c in document.get('components', []))
        coordinates[view] = identities(current) == identities(previous)
        assert coordinates[view], 'Acquisition changed component identities'
    baseline = json.loads((ROOT / 'benchmarks/results/jar-content-budget-v1/report.json').read_bytes())
    for view in ('final', 'os', 'full'):
        shutil.copyfile(analysis / (view + '.cdx.json'), output_file(output, view + '.cdx.json'))
    atomic_json(output / 'report.json', {
        'status': 'ACQUISITION_AND_ANALYSIS_COMPLETED', 'runtime_changed': False,
        'mode': ('external loopback HTTP fixture' if http_fixture else
                 'external authenticated TLS loopback fixture; explicit fixture CA, no insecure flag'),
        'negative_transport_checks': negative,
        'tool': provenance, 'docker_invoked': False, 'project_executed': False,
        'oracle_read_by_predictor': False, 'manifest_digest': fixture.manifest['digest'],
        'config_digest': config, 'diff_ids': layers, 'requests': fixture.requests,
        'archive_bytes': acquired.stat().st_size, 'pull_seconds': pull_seconds,
        'analysis_seconds': analysis_seconds, 'archive_reads': stats,
        'previous_reads': baseline['archive_reads'], 'three_views_schema_valid': True,
        'component_coordinates_equal_r89': coordinates,
        'catalog_bytes': (analysis / 'image.syft.json').stat().st_size,
        'limitations': ['No cross-host redirect/credential-helper attack tests or runtime integration yet',
                        'Archive size is sampled, not a strict filesystem quota',
                        'Large/nested/resource JAR and direct/identity quality unchanged',
                        'No new accuracy or independent-control claim; prototype only']})
    print(json.dumps({'pull_seconds': pull_seconds, 'analysis_seconds': analysis_seconds,
                      'reads': stats, 'config_digest': config}))


def output_file(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    return directory / name


if __name__ == '__main__':
    main()

"""Trusted, ephemeral benchmark fixture only; never part of service runtime."""
import hashlib
import json
import re
import shutil
import tarfile
from http.server import BaseHTTPRequestHandler


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



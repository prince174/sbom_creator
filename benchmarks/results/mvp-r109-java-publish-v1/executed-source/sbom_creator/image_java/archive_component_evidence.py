"""Complete delivered JAR proof, separate from class/resource payload."""
import hashlib
import re
import time

from packageurl import PackageURL

from ..core import artifact_identity
from . import bounded_jar_evidence as limits
from .directory_jar_evidence import JarFiles as DirectoryJarFiles
from .stored_jar_evidence import CachedWindow
from .trivy_payload_bridge import artifact_key, canonical_path

MAX_METADATA = 32 * 1024
COORDINATE = re.compile(r'[A-Za-z0-9_.-]+')


def properties_identity(raw, member_name):
    """Strict supported subset; ambiguous/escaped Java properties stay UNKNOWN."""
    text = raw.decode('ascii')
    if '\\' in text or any(ord(c) < 32 and c not in '\r\n\t' for c in text):
        raise ValueError('Unsupported Maven properties encoding')
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not separator or key in values:
            raise ValueError('Ambiguous Maven properties')
        values[key] = value
    group, name, version = (values.get(key, '') for key in ('groupId', 'artifactId', 'version'))
    if (not all(COORDINATE.fullmatch(value) for value in (group, name, version))
            or member_name != f'META-INF/maven/{group}/{name}/pom.properties'):
        raise ValueError('Maven properties and canonical archive path disagree')
    purl = PackageURL(type='maven', namespace=group, name=name, version=version).to_string()
    if not artifact_identity({'purl': purl, 'name': name, 'version': version,
                              'type': 'java-archive'})['identity_valid']:
        raise ValueError('Nonconcrete Maven properties identity')
    return purl


class JarFiles(DirectoryJarFiles):
    def __init__(self, archive, document, *, temporary=None):
        super().__init__(archive, document, temporary=temporary)
        self.component_hashes = {}
        self.stats.update(archive_hash_verifications=0, archive_components_confirmed=0,
                          archive_crc_read_bytes=0)

    def validate_contents(self, archive):
        """CRC-check every member without exceeding the existing ordinary-read cap."""
        for member in archive.infolist():
            if member.is_dir():
                continue
            if (member.file_size > limits.MAX_NESTED
                    or member.file_size > max(1, member.compress_size)*limits.MAX_RATIO
                    or member.file_size > 128*limits.CHUNK-self.stats['ordinary_read_bytes']):
                raise limits.BudgetExceeded('Archive CRC validation read budget')
            length = 0
            with archive.open(member) as raw:
                while True:
                    if time.monotonic()-self.started > 180:
                        raise limits.BudgetExceeded('Witness job deadline')
                    block = raw.read(limits.CHUNK)
                    if not block:
                        break
                    length += len(block)
                    self.stats['ordinary_read_bytes'] += len(block)
                    self.stats['archive_crc_read_bytes'] += len(block)
            if length != member.file_size:
                raise ValueError('Truncated archive member CRC validation')

    def full_hashes(self, stream, expected_sha256):
        if not isinstance(stream, CachedWindow) or stream.closed or stream.window.closed:
            raise ValueError('Unsupported or closed physical archive window')
        view = stream.window
        key = id(view.stream), view.offset, view.size
        if key not in self.component_hashes:
            if view.size > 8*1024**3-self.stats['verification_read_bytes']:
                raise limits.BudgetExceeded('Content verification read budget')
            sha256, sha1, remaining = hashlib.sha256(), hashlib.sha1(), view.size
            view.stream.seek(view.offset)
            while remaining:
                if time.monotonic()-self.started > 180:
                    raise limits.BudgetExceeded('Witness job deadline')
                raw = view.stream.read(min(1024*1024, remaining))
                if not raw:
                    raise ValueError('Truncated complete archive verification')
                sha256.update(raw)
                sha1.update(raw)
                remaining -= len(raw)
                self.stats['verification_read_bytes'] += len(raw)
            self.component_hashes[key] = sha256.hexdigest(), sha1.hexdigest()
            self.stats['archive_hash_verifications'] += 1
        digest, sha1 = self.component_hashes[key]
        if digest != expected_sha256:
            raise ValueError('Physical archive differs from verified chain')
        return digest, sha1

    def component(self, artifact):
        """No identity guessed from a filename, manifest title, or peer catalog."""
        if time.monotonic()-self.started > 180:
            raise limits.BudgetExceeded('Witness job deadline')
        files = {name: [item] for name, item in self.files.items()}
        target, layer = artifact_key(artifact, files)
        location = artifact['locations'][0]
        outer = canonical_path(location['path'])
        virtual = artifact.get('metadata', {}).get('virtualPath', outer)
        source = self.source(outer)
        if (outer, source.window.size) not in self.file_hashes:
            super().witness(artifact)  # Establish full outer SHA and checked nested CRCs.
        key, stream = (outer,), source
        try:
            nested = virtual[len(outer):].lstrip(':').split(':') if virtual != outer else []
            if len(nested) > limits.MAX_DEPTH:
                raise limits.BudgetExceeded('Nested archive depth')
            for inner in nested:
                archive = self.archive(key, stream)
                member = archive.getinfo(inner)
                key += (member.filename,)
                if key not in self.spools:
                    if (member.file_size > limits.MAX_NESTED
                            or member.file_size > max(1, member.compress_size)*limits.MAX_RATIO):
                        raise limits.BudgetExceeded('Nested archive inflate budget')
                    self.nested(key, archive, member, stream)
                stream = self.spools[key]
                if not isinstance(stream, CachedWindow):
                    raise TypeError('Archive presence requires a verified physical window')
            archive = self.archive(key, stream)
            view = stream.window
            if nested:
                verified = self.verified_stored.get((id(view.stream), view.offset, view.size))
                if verified is None:
                    raise ValueError('Missing complete nested-member CRC proof')
                expected_sha256 = verified[0]
            else:
                expected_sha256 = self.file_hashes.get((outer, view.size))
                if expected_sha256 is None:
                    raise ValueError('Missing complete outer archive proof')
            sha256, sha1 = self.full_hashes(stream, expected_sha256)
            self.validate_contents(archive)
            members = [m for m in archive.infolist() if m.filename.startswith('META-INF/maven/')
                       and m.filename.endswith('/pom.properties')]
            if len(members) > 1:
                raise ValueError('Multiple embedded Maven archive identities')
            identity = None
            if members:
                member = members[0]
                if (member.file_size > MAX_METADATA
                        or member.file_size > max(1, member.compress_size)*limits.MAX_RATIO
                        or member.file_size > 128*limits.CHUNK-self.stats['ordinary_read_bytes']):
                    raise ValueError('Maven metadata budget')
                with archive.open(member) as raw:
                    content = raw.read(MAX_METADATA+1)  # Complete read verifies this entry's CRC.
                self.stats['ordinary_read_bytes'] += len(content)
                if len(content) != member.file_size:
                    raise ValueError('Truncated Maven archive metadata')
                identity = properties_identity(content, member.filename)
            return {'status': 'confirmed', 'kind': 'complete_java_archive', 'path': target,
                'virtual_path': virtual, 'layer': layer,
                'image_config_digest': self.layers_reader.config_digest,
                'sha256': sha256, 'sha1': sha1, 'bytes': view.size,
                'chain_verified': True, 'zip_crc_verified': True, 'metadata_identity': identity,
                'nested_crc_verified': bool(nested),
                'scope': 'Delivered archive bytes; no class/resource, execution or publisher-authentication claim'}
        finally:
            for archive in self.zips.values():
                archive.close()
            self.zips.clear()

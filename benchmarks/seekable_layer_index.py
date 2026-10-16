"""Experimental internal layer normalization and bounded seekable file views.

No project execution, filesystem extraction, identities or direct-edge inference.
Disk acquisition and TAR metadata have separate explicit budgets; ZIP/payload
budgets are not changed by this module.
"""
import gzip
import hashlib
import io
import json
import posixpath
import re
import tarfile
import tempfile
import time
from contextlib import ExitStack

CHUNK = 1024 * 1024
MAX_DISK = 8 * 1024**3
MAX_METADATA = 16 * CHUNK
MAX_EXTENSION = 64 * 1024
MAX_ENTRIES = 100_000
MAX_READ = 32 * CHUNK
MAX_READ_TOTAL = 128 * CHUNK
MAX_RATIO = 200
MAX_SECONDS = 120


def canonical(name):
    while name.startswith('./'):
        name = name[2:]
    if name in ('', '.'):
        return '/'
    if (name.startswith('/') or '\\' in name or ':' in name or '\x00' in name or
            '..' in name.split('/') or len(name.encode('utf-8')) > 4096):
        raise ValueError('Unsafe TAR path')
    return '/' + posixpath.normpath(name)


def preflight(stream, size):
    """Bound extension allocation BEFORE handing bytes to tarfile's parser."""
    offset, cost, entries, chain = 0, 0, 0, 0
    # Global PAX dictionaries can multiply retained metadata across entries.
    extensions = (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
    allowed = (*extensions, tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.LNKTYPE, tarfile.SYMTYPE)
    while offset + 512 <= size:
        stream.seek(offset)
        header = stream.read(512)
        if header == bytes(512):
            if stream.read(512) != bytes(512):
                raise ValueError('Missing TAR end marker')
            while data := stream.read(CHUNK):
                if any(data):
                    raise ValueError('Nonzero trailing TAR data')
            stream.seek(0)
            return {'metadata_cost': cost, 'headers': entries}
        member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        entries += 1
        cost += 1024 + len(member.name.encode('utf-8'))
        if member.type not in allowed or member.size < 0:
            raise ValueError('Unsupported TAR record')
        if member.type not in (*extensions, tarfile.REGTYPE, tarfile.AREGTYPE) and member.size:
            raise ValueError('Nonregular TAR payload')
        if member.type in extensions:
            chain += 1
            if chain > 8:
                raise ValueError('TAR extension chain budget')
            if member.size > MAX_EXTENSION:
                raise ValueError('TAR extension budget')
            extension = stream.read(member.size)
            cost += member.size
            if len(extension) != member.size:
                raise ValueError('Truncated TAR extension')
            if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                # Size overrides/sparse maps change record layout; unsupported.
                cursor = 0
                while cursor < len(extension):
                    space = extension.find(b' ', cursor)
                    if space < 0 or space-cursor > 10:
                        raise ValueError('Invalid PAX record')
                    length = int(extension[cursor:space])
                    end = cursor + length
                    if end > len(extension) or end <= space+1 or extension[end-1:end] != b'\n':
                        raise ValueError('Invalid PAX length')
                    key = extension[space+1:end-1].split(b'=', 1)[0]
                    if key == b'size' or key.startswith((b'GNU.sparse', b'SCHILY.realsize')):
                        raise ValueError('Unsupported PAX layout')
                    cursor = end
        else:
            chain = 0
        if cost > MAX_METADATA or entries > MAX_ENTRIES:
            raise ValueError('TAR metadata budget')
        offset += 512 + ((member.size+511)//512)*512
        if offset > size:
            raise ValueError('Truncated TAR body')
    raise ValueError('Missing TAR terminator')


def index(stream, size, remaining=None):
    stats = preflight(stream, size)
    if remaining is not None and stats['metadata_cost'] > remaining:
        raise ValueError('Aggregate metadata budget')
    archive = tarfile.open(fileobj=stream, mode='r:')  # noqa: SIM115 -- caller owns returned archive
    result = {}
    try:
        for member in archive:
            name = canonical(member.name)
            if name in result:
                raise ValueError('Duplicate canonical TAR path')
            if member.issparse():
                raise ValueError('Sparse TAR unsupported')
            result[name] = member
    except BaseException:
        archive.close()
        raise
    return archive, result, stats


class Window(io.RawIOBase):
    def __init__(self, owner, stream, offset, size):
        self.owner, self.stream, self.offset, self.size, self.position = owner, stream, offset, size, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        if self.closed:
            raise ValueError('Closed file view')
        if whence not in (0, 1, 2):
            raise ValueError('Invalid seek origin')
        value = offset + (0 if whence == 0 else self.position if whence == 1 else self.size)
        if value < 0 or value > self.size:
            raise ValueError('Seek outside bound file')
        self.position = value
        return value

    def read(self, size=-1):
        if self.closed:
            raise ValueError('Closed file view')
        size = self.size-self.position if size < 0 else min(size, self.size-self.position)
        if size > MAX_READ or size > MAX_READ_TOTAL-self.owner.stats['payload_read_bytes']:
            raise ValueError('Payload read budget')
        self.stream.seek(self.offset+self.position)
        raw = self.stream.read(size)
        if len(raw) != size:
            raise ValueError('Truncated bound file')
        self.position += len(raw)
        self.owner.stats['payload_read_bytes'] += len(raw)
        return raw


class Layers:
    def __init__(self, path):
        self.stack = ExitStack()
        self.stats = {'normalized_bytes': 0, 'metadata_cost': 0, 'headers': 0,
                      'payload_read_bytes': 0, 'normalizations': 0}
        self.ready, self.failed = {}, {}
        try:
            stream = self.stack.enter_context(open(path, 'rb'))  # noqa: SIM115 -- ExitStack owns it
            stream.seek(0, 2)
            size = stream.tell()
            if size > MAX_DISK:
                raise ValueError('Input archive budget')
            archive, entries, outer_stats = index(stream, size)
            self.stack.enter_context(archive)
            self.stats.update(metadata_cost=outer_stats['metadata_cost'], headers=outer_stats['headers'])

            def document(name):
                member = entries.get(canonical(name))
                if member is None or not member.isfile() or member.size > 4*CHUNK:
                    raise ValueError('Invalid image metadata')
                return json.loads(archive.extractfile(member).read())
            manifests = document('manifest.json')
            if len(manifests) != 1:
                raise ValueError('Ambiguous image manifest')
            manifest = manifests[0]
            config_member = entries[canonical(manifest['Config'])]
            config = document(manifest['Config'])
            raw = archive.extractfile(config_member).read()
            self.config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            self.mapping = dict(zip(config['rootfs']['diff_ids'], manifest['Layers'], strict=True))
            if len(self.mapping) != len(manifest['Layers']):
                raise ValueError('Duplicate layer binding')
            self.outer, self.entries = archive, entries
        except BaseException:
            self.stack.close()
            raise

    def close(self):
        self.stack.close()

    def layer(self, diff_id):
        if diff_id in self.failed:
            raise ValueError('Previously rejected layer')
        if diff_id in self.ready:
            return self.ready[diff_id]
        attempt = ExitStack()
        try:
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', diff_id):
                raise ValueError('Invalid DiffID')
            member = self.entries[canonical(self.mapping[diff_id])]
            if not member.isfile():
                raise ValueError('Layer is not regular')
            compressed = attempt.enter_context(self.outer.extractfile(member))
            prefix = compressed.read(2)
            compressed.seek(0)
            source = attempt.enter_context(gzip.GzipFile(fileobj=compressed)) if prefix == b'\x1f\x8b' else compressed
            spool = attempt.enter_context(tempfile.TemporaryFile())  # noqa: SIM115 -- ExitStack owns it
            digest, size, started = hashlib.sha256(), 0, time.monotonic()
            while data := source.read(CHUNK):
                if (len(data) > MAX_DISK-self.stats['normalized_bytes'] or
                        size+len(data) > max(1, member.size)*MAX_RATIO or time.monotonic()-started > MAX_SECONDS):
                    raise ValueError('Layer normalization budget')
                spool.write(data)
                digest.update(data)
                size += len(data)
                self.stats['normalized_bytes'] += len(data)
            if 'sha256:'+digest.hexdigest() != diff_id:
                raise ValueError('Layer DiffID mismatch')
            archive, entries, stats = index(spool, size, MAX_METADATA-self.stats['metadata_cost'])
            attempt.enter_context(archive)
            self.stats['metadata_cost'] += stats['metadata_cost']
            self.stats['headers'] += stats['headers']
            self.stats['normalizations'] += 1
            self.ready[diff_id] = spool, entries
            self.stack.enter_context(attempt)
            return self.ready[diff_id]
        except BaseException:
            self.failed[diff_id] = True
            attempt.close()
            raise

    def view(self, name, diff_id, expected_size):
        stream, entries = self.layer(diff_id)
        member = entries.get(canonical(name.lstrip('/')))
        if member is None or not member.isfile() or member.size != expected_size:
            raise ValueError('Final file metadata mismatch')
        return Window(self, stream, member.offset_data, member.size)

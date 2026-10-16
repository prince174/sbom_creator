"""Experimental disk-backed JAR witnesses; never import build reference labels.

No runtime integration. Large outer files are spooled in 1MiB chunks under a
separate cumulative disk budget, never loaded as a large bytes object. ZIP
central-directory bounds are checked before Python allocates its entry index.
Witnesses prove bytes present, not execution, directness or coordinate identity.
"""
from __future__ import annotations

import posixpath
import stat
import struct
import tarfile
import tempfile
import zipfile

from .. import payload

CHUNK = 1024 * 1024
MAX_OUTER = 128 * CHUNK
MAX_NESTED = payload.MAX_READ
MAX_COPY = 256 * CHUNK
MAX_INDEX = 2 * CHUNK
MAX_INDEX_TOTAL = 16 * CHUNK
MAX_ENTRIES = 100_000
MAX_LAYER_BYTES = 512 * CHUNK
MAX_RATIO = 200
MAX_DEPTH = 8
RESOURCE_SUFFIXES = {'.js', '.css', '.html', '.json', '.xml', '.properties', '.yaml', '.yml',
                     '.svg', '.png', '.gif', '.jpg', '.woff', '.woff2', '.ttf', '.sql'}
BUILD_METADATA = {'pom.xml', 'pom.properties', 'package.json', 'bower.json'}


class BudgetExceeded(ValueError):
    pass


def zip_index(stream):
    """Reject oversized/ZIP64/multidisk indexes before ZipFile reads the CD."""
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(max(0, size - 65_557))
    tail = stream.read(65_557)
    offset = tail.rfind(b'PK\x05\x06')
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError('Missing ZIP directory')
    _, disk, cd_disk, on_disk, entries, cd_size, cd_offset, comment = struct.unpack_from('<4s4H2LH', tail, offset)
    if disk or cd_disk or on_disk != entries or entries == 0xffff or cd_size == 0xffffffff:
        raise ValueError('Multidisk or ZIP64 unsupported')
    if len(tail) - offset != 22 + comment or cd_offset + cd_size > size - len(tail) + offset:
        raise ValueError('Inconsistent ZIP directory')
    if cd_size > MAX_INDEX or entries > MAX_ENTRIES:
        raise BudgetExceeded('ZIP directory budget')
    return entries, cd_size


def safe_member(member):
    name = member.orig_filename
    if (name != member.filename or '\x00' in name or '\\' in name or name.startswith('/') or ':' in name
            or '..' in name.split('/') or posixpath.normpath(name).lstrip('./') != name.rstrip('/')):
        return False
    mode = member.external_attr >> 16
    return not stat.S_ISLNK(mode) and not member.flag_bits & 1


class JarFiles(payload.ImageFiles):
    """Use only Syft's final-file/layer map; never search deleted image layers."""
    def __init__(self, archive, document, *, temporary=None):
        # Only a seekable plain outer tar is supported by this prototype.
        with open(archive, 'rb') as stream:
            if stream.read(2) == b'\x1f\x8b':
                raise ValueError('Compressed outer image archive unsupported')
        super().__init__(archive, document)
        self.temporary = temporary
        self.spools = {}
        self.zips = {}
        self.stats = {'copied_bytes': 0, 'ordinary_read_bytes': 0, 'index_bytes': 0,
                      'zip_entries': 0, 'source_files': 0, 'nested_files': 0,
                      'class_witnesses': 0, 'resource_witnesses': 0, 'rejections': 0}

    def read(self, name, limit=payload.MAX_READ):
        limit = min(limit, payload.MAX_READ)
        size = self.files.get(payload.path(name), {}).get('metadata', {}).get('size', 0)
        if size > limit or size > 128 * CHUNK - self.stats['ordinary_read_bytes']:
            return None
        raw = super().read(name, limit)
        if raw is not None:
            self.stats['ordinary_read_bytes'] += len(raw)
        return raw

    def copy(self, source, size, cap):
        if len(self.spools) >= 256 or size < 0 or size > cap or size > MAX_COPY - self.stats['copied_bytes']:
            raise BudgetExceeded('Disk copy budget')
        output = self.stack.enter_context(tempfile.TemporaryFile(dir=self.temporary))  # noqa: SIM115 -- ExitStack owns it
        remaining = size
        while remaining:
            data = source.read(min(CHUNK, remaining))
            if not data:
                raise ValueError('Truncated artifact stream')
            output.write(data)
            remaining -= len(data)
            self.stats['copied_bytes'] += len(data)
        if source.read(1):
            raise ValueError('Artifact exceeds declared size')
        output.seek(0)
        return output

    def source(self, name):
        name = payload.path(name)
        key = (name,)
        if key in self.spools:
            return self.spools[key]
        if not self.regular(name):
            raise ValueError('No final regular file')
        entry = self.files[name]
        size = entry['metadata']['size']
        if size > MAX_OUTER or size > MAX_COPY - self.stats['copied_bytes']:
            raise BudgetExceeded('Outer artifact disk budget')
        layer_id = entry['location'].get('layerID')
        if layer_id not in self.layers:
            raise ValueError('Missing final layer')
        if layer_id not in self.opened:
            member = self.outer.getmember(self.layers[layer_id])
            if not member.isfile():
                raise ValueError('Layer is not a regular file')
            stream = self.stack.enter_context(self.outer.extractfile(member))
            layer = self.stack.enter_context(tarfile.open(fileobj=stream, mode='r:*'))  # noqa: SIM115 -- ExitStack owns it
            members, expanded = {}, 0
            for count, item in enumerate(layer):
                expanded += item.size
                if count >= 300_000 or expanded > MAX_LAYER_BYTES:
                    raise BudgetExceeded('Layer index/expanded-byte budget')
                normalized = payload.path(item.name)
                if normalized in members:
                    raise ValueError('Ambiguous layer path')
                members[normalized] = item
            self.opened[layer_id] = layer, members
        layer, members = self.opened[layer_id]
        member = members.get(name)
        if member is None or not member.isfile() or member.size != size:
            raise ValueError('Final file and layer metadata disagree')
        with layer.extractfile(member) as stream:
            self.spools[key] = self.copy(stream, size, MAX_OUTER)
        self.stats['source_files'] += 1
        return self.spools[key]

    def archive(self, key, stream):
        if key in self.zips:
            return self.zips[key]
        entries, size = zip_index(stream)
        if (size > MAX_INDEX_TOTAL - self.stats['index_bytes']
                or entries > MAX_ENTRIES - self.stats['zip_entries'] or len(self.zips) >= 256):
            raise BudgetExceeded('Aggregate ZIP index budget')
        # Charge unsuccessful parses too; repeated malformed input is not free.
        self.stats['index_bytes'] += size
        self.stats['zip_entries'] += entries
        archive = self.stack.enter_context(zipfile.ZipFile(stream))
        items = archive.infolist()
        if len(items) != entries or len({item.filename for item in items}) != len(items):
            raise ValueError('Ambiguous ZIP entry index')
        if any(not safe_member(item) for item in items):
            raise ValueError('Unsafe ZIP member')
        self.zips[key] = archive
        return archive

    def witness(self, artifact):
        for location in artifact.get('locations', []):
            outer = payload.path(location.get('path', ''))
            virtual = artifact.get('metadata', {}).get('virtualPath', outer)
            if virtual != outer and not virtual.startswith(outer + ':'):
                continue
            nested = virtual[len(outer):].lstrip(':').split(':') if virtual != outer else []
            if len(nested) > MAX_DEPTH:
                raise BudgetExceeded('Nested archive depth')
            key = (outer,)
            stream = self.source(outer)
            for inner in nested:
                archive = self.archive(key, stream)
                member = archive.getinfo(inner.lstrip('/'))
                key += (member.filename,)
                if key not in self.spools:
                    if member.file_size > MAX_NESTED or member.file_size > max(1, member.compress_size) * MAX_RATIO:
                        raise BudgetExceeded('Nested archive inflate budget')
                    with archive.open(member) as raw:
                        self.spools[key] = self.copy(raw, member.file_size, MAX_NESTED)
                    self.stats['nested_files'] += 1
                stream = self.spools[key]
            archive = self.archive(key, stream)
            for member in archive.infolist():
                if member.filename.endswith('.class') and member.file_size >= 4:
                    if member.file_size > MAX_NESTED or member.file_size > max(1, member.compress_size) * MAX_RATIO:
                        continue
                    with archive.open(member) as raw:
                        if raw.read(4) == b'\xca\xfe\xba\xbe':
                            self.stats['class_witnesses'] += 1
                            return virtual + ':' + member.filename
            for member in archive.infolist():
                name = member.filename
                if (member.is_dir() or not member.file_size or name.startswith('META-INF/')
                        and not name.startswith('META-INF/resources/')
                        or posixpath.basename(name).lower() in BUILD_METADATA
                        or posixpath.splitext(name)[1].lower() not in RESOURCE_SUFFIXES):
                    continue
                if member.file_size > MAX_NESTED or member.file_size > max(1, member.compress_size) * MAX_RATIO:
                    continue
                with archive.open(member) as raw:
                    if raw.read(1):
                        self.stats['resource_witnesses'] += 1
                        return virtual + ':' + name
        return None

"""Bounded JAR witnesses through hash-bound image layer windows."""
import hashlib
import io
import struct
import time
import zipfile
import zlib
from contextlib import ExitStack

from .. import payload
from . import bounded_jar_evidence as frozen
from .seekable_layer_index import Layers, Window


class CachedWindow(io.RawIOBase):
    """Bounded exact physical-range cache, shared only inside this image reader."""
    def __init__(self, owner, window):
        self.owner, self.window = owner, window

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.window.tell()

    def seek(self, offset, whence=0):
        if self.closed or self.window.closed:
            raise ValueError('Closed cached view')
        return self.window.seek(offset, whence)

    def read(self, size=-1):
        if self.closed or self.window.closed:
            raise ValueError('Closed cached view')
        position = self.window.tell()
        amount = min(size, self.window.size-position) if size >= 0 else self.window.size-position
        key = (id(self.window.stream), self.window.offset+position, amount)
        if key in self.owner.read_cache:
            self.window.seek(amount, 1)
            self.owner.stats['read_cache_hits'] += 1
            return self.owner.read_cache[key]
        raw = self.window.read(size)
        if (len(self.owner.read_cache) < 4096 and len(raw) <= frozen.MAX_INDEX and
                len(raw) <= frozen.MAX_INDEX_TOTAL-self.owner.cache_bytes):
            self.owner.read_cache[key] = raw
            self.owner.cache_bytes += len(raw)
            self.owner.stats['range_cache_bytes'] = self.owner.cache_bytes
            self.owner.stats['range_cache_entries'] = len(self.owner.read_cache)
        return raw


def directory(stream):
    """Fast zero-comment EOCD; keep the frozen bounded fallback for comments."""
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(max(0, size-22))
    end = stream.read(22)
    if len(end) != 22 or end[:4] != b'PK\x05\x06' or end[-2:] != b'\0\0':
        entries, length = frozen.zip_index(stream)
        stream.seek(max(0, size-65557))
        tail = stream.read(65557)
        end_position = tail.rfind(b'PK\x05\x06')
        offset = struct.unpack_from('<L', tail, end_position+16)[0]
        directory_end = size-len(tail)+end_position
    else:
        _, disk, cd_disk, on_disk, entries, length, offset, _ = struct.unpack('<4s4H2LH', end)
        if disk or cd_disk or on_disk != entries or entries == 0xffff or length == 0xffffffff:
            raise ValueError('Multidisk or ZIP64 unsupported')
        if offset+length > size-22:
            raise ValueError('Inconsistent ZIP directory')
        directory_end = size-22
    if offset+length != directory_end:
        raise ValueError('Unsupported ZIP offset layout')
    if length > frozen.MAX_INDEX or entries > frozen.MAX_ENTRIES:
        raise frozen.BudgetExceeded('ZIP directory budget')
    stream.seek(offset)
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError('Truncated ZIP directory')
    return entries, length, (size, offset, entries, hashlib.sha256(raw).hexdigest())


class JarFiles(frozen.JarFiles):
    def __init__(self, archive, document, *, temporary=None):
        # Validate TAR layout before any general-purpose parser sees it. Do not
        # run the legacy ImageFiles initializer, which indexes an unchecked TAR.
        self.stack = ExitStack()
        try:
            self.layers_reader = Layers(archive, temporary=temporary)
            self.stack.callback(self.layers_reader.close)
            self.files = {}
            for entry in document.get('files', []):
                name = payload.path(entry['location']['path'])
                if name in self.files:
                    raise ValueError('Ambiguous final filesystem path')
                self.files[name] = entry
            self.paths = sorted(self.files)
        except BaseException:
            self.close()
            raise
        self.temporary = temporary
        self.spools, self.zips = {}, {}
        self.stats = {'copied_bytes': 0, 'ordinary_read_bytes': 0, 'index_bytes': 0,
                      'zip_entries': 0, 'source_files': 0, 'nested_files': 0,
                      'class_witnesses': 0, 'resource_witnesses': 0, 'rejections': 0}
        if self.layers_reader.config_digest != document['source']['metadata']['imageID']:
            self.close()
            raise ValueError('Physical config differs from catalog')
        self.indexes = set()
        self.read_cache, self.cache_bytes = {}, 0
        self.file_hashes, self.confirmed_content = {}, {}
        self.verified_stored = {}
        self.started = time.monotonic()
        self.stats.update(zip_parse_entries=0, views=0, read_cache_hits=0,
                          verification_read_bytes=0, content_witness_hits=0,
                          nested_window_files=0, nested_window_bytes=0,
                          range_cache_bytes=0, range_cache_entries=0, stored_crc_verifications=0)

    def read(self, name, limit=payload.MAX_READ):
        name = payload.path(name)
        if not self.regular(name):
            return None
        item = self.files[name]
        size = item['metadata']['size']
        if size > min(limit, payload.MAX_READ, 128*frozen.CHUNK-self.stats['ordinary_read_bytes']):
            return None
        with self.layers_reader.view(name, item['location']['layerID'], size) as view:
            raw = view.read(size)
        self.stats['ordinary_read_bytes'] += len(raw)
        return raw

    def source(self, name):
        name = payload.path(name)
        key = (name,)
        if key in self.spools:
            return self.spools[key]
        if not self.regular(name):
            raise ValueError('No final regular file')
        if self.stats['views'] >= 4096:
            raise frozen.BudgetExceeded('File view budget')
        item = self.files[name]
        if item['metadata']['size'] > frozen.MAX_OUTER:
            raise frozen.BudgetExceeded('Outer archive size budget')
        view = self.layers_reader.view(name, item['location']['layerID'], item['metadata']['size'])
        self.stack.enter_context(view)
        self.spools[key] = self.stack.enter_context(CachedWindow(self, view))
        self.stats['views'] += 1
        return self.spools[key]

    def archive(self, key, stream):
        if key in self.zips:
            return self.zips[key]
        entries, length, fingerprint = directory(stream)
        if fingerprint not in self.indexes:
            if (len(self.indexes) >= 256 or length > frozen.MAX_INDEX_TOTAL-self.stats['index_bytes'] or
                    entries > frozen.MAX_ENTRIES-self.stats['zip_entries']):
                raise frozen.BudgetExceeded('Unique ZIP directory budget')
            self.indexes.add(fingerprint)
            self.stats['index_bytes'] += length
            self.stats['zip_entries'] += entries
        archive = zipfile.ZipFile(stream)
        try:
            items = archive.infolist()
            self.stats['zip_parse_entries'] += len(items)
            if len(items) != entries or len({m.filename for m in items}) != len(items):
                raise ValueError('Ambiguous ZIP directory')
            if any(not frozen.safe_member(m) for m in items):
                raise ValueError('Unsafe ZIP member')
            self.zips[key] = archive
            return archive
        except BaseException:
            archive.close()
            raise

    def nested(self, key, archive, member, stream):
        # STORED members are already exact byte ranges of the verified layer.
        # Bound a subwindow instead of copying the whole nested JAR just to read
        # its directory and one class/resource. Compression/descriptor cases keep
        # the existing bounded decompression path and its CRC verification.
        if (not isinstance(stream, CachedWindow) or member.compress_type != zipfile.ZIP_STORED
                or member.flag_bits & 8):
            return super().nested(key, archive, member, stream)
        if self.stats['views'] >= 4096:
            raise frozen.BudgetExceeded('File view budget')
        stream.seek(member.header_offset)
        header = stream.read(30)
        if len(header) != 30:
            raise ValueError('Truncated stored ZIP header')
        signature, version, flags, method, _, _, crc, compressed, size, name_length, extra_length = struct.unpack('<4s5H3L2H', header)
        if (signature != b'PK\x03\x04' or version != member.extract_version or flags != member.flag_bits
                or flags & ~0x800 or method != zipfile.ZIP_STORED or crc != member.CRC
                or compressed != member.compress_size or size != member.file_size or compressed != size):
            raise ValueError('Stored ZIP local and central headers disagree')
        start = member.header_offset+30+name_length+extra_length
        if start < 0 or start > stream.window.size-size:
            raise ValueError('Stored ZIP body outside parent archive')
        # Use the standard parser for local filename, encryption, supported
        # version and overlap checks, without asking it to read/inflate the body.
        with archive.open(member):
            pass
        window = self.stack.enter_context(Window(self.layers_reader, stream.window.stream,
            stream.window.offset+start, size))
        self.stats['views'] += 1
        try:
            self.verify_stored(window, member.CRC)
        except BaseException:
            window.close()
            raise
        self.spools[key] = self.stack.enter_context(CachedWindow(self, window))
        self.stats['nested_files'] += 1
        self.stats['nested_window_files'] += 1
        self.stats['nested_window_bytes'] += size  # bound bytes, not bytes copied/read

    def verify_stored(self, window, expected_crc):
        # Keep the full-member CRC check formerly performed while copying the
        # nested member. These complete SHA256+CRC reads use the SAME existing
        # 8GiB verification budget; they are never used as class/resource probes.
        key = (id(window.stream), window.offset, window.size)
        if key not in self.verified_stored:
            if window.size > 8*1024**3-self.stats['verification_read_bytes']:
                raise frozen.BudgetExceeded('Content verification read budget')
            digest, crc, remaining = hashlib.sha256(), 0, window.size
            window.stream.seek(window.offset)
            while remaining:
                if time.monotonic()-self.started > 180:
                    raise frozen.BudgetExceeded('Witness job deadline')
                raw = window.stream.read(min(1024*1024, remaining))
                if not raw:
                    raise ValueError('Truncated stored member verification')
                digest.update(raw)
                crc = zlib.crc32(raw, crc)
                self.stats['verification_read_bytes'] += len(raw)
                remaining -= len(raw)
            self.verified_stored[key] = digest.hexdigest(), crc
            self.stats['stored_crc_verifications'] += 1
        if self.verified_stored[key][1] != expected_crc:
            raise ValueError('Stored ZIP body CRC differs from directory')

    def witness(self, artifact):
        if time.monotonic()-self.started > 180:
            raise frozen.BudgetExceeded('Witness job deadline')
        try:
            # A content hash is re-derived from every physical file, never from
            # the reference or scanner's guessed identity. Only payload evidence
            # is shared; each path/layer/identity still passes the frozen bridge.
            locations = artifact.get('locations', [])
            if len(locations) != 1:
                return super().witness(artifact)
            outer = payload.path(locations[0].get('path', ''))
            virtual = artifact.get('metadata', {}).get('virtualPath', outer)
            if virtual != outer and not virtual.startswith(outer+':'):
                return None
            view = self.source(outer).window
            key = (outer, view.size)
            if key not in self.file_hashes:
                if view.size > 8*1024**3-self.stats['verification_read_bytes']:
                    raise frozen.BudgetExceeded('Content verification read budget')
                digest, remaining = hashlib.sha256(), view.size
                view.stream.seek(view.offset)
                while remaining:
                    if time.monotonic()-self.started > 180:
                        raise frozen.BudgetExceeded('Witness job deadline')
                    raw = view.stream.read(min(1024*1024, remaining))
                    if not raw:
                        raise ValueError('Truncated content verification')
                    digest.update(raw)
                    self.stats['verification_read_bytes'] += len(raw)
                    remaining -= len(raw)
                self.file_hashes[key] = digest.hexdigest()
            content = self.file_hashes[key], virtual[len(outer):]
            if content in self.confirmed_content:
                self.stats['content_witness_hits'] += 1
                return virtual+self.confirmed_content[content]
            result = super().witness(artifact)
            if result and result.startswith(virtual+':'):
                self.confirmed_content[content] = result[len(virtual):]
            return result
        finally:
            # Each witness retains at most its bounded nested chain, not thousands
            # of duplicated parsed indexes. No ZipFile internals are shared.
            for archive in self.zips.values():
                archive.close()
            self.zips.clear()
            # Raw-byte cache remains bounded at16MiB/4096 exact physical ranges.
            # Parsed ZIP objects are never shared between witnesses.

"""Stage, validate and atomically publish the public Java identity database.

Only an absent cache is populated. Existing invalid files and stale locks are
preserved for operator inspection; no automatic destructive recovery or refresh.
This validates the supported format/index, not full integrity or authenticity.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .public_hash_identity import MAX_DATABASE_BYTES, PublicJavaHashLookup

MAX_METADATA_BYTES = 16 * 1024
MAX_STAGE_BYTES = 2 * 1024**3
MAX_STAGE_ENTRIES = 10_000
TIMESTAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})')
ERROR_CODES = frozenset({'CACHE_INVALID', 'BOOTSTRAP_BUSY', 'DOWNLOAD_FAILED',
                         'DOWNLOAD_INVALID', 'PUBLICATION_FAILED'})


class DatabaseCacheError(ValueError):
    """Only fixed internal codes may appear in exported acquisition diagnostics."""

    def __init__(self, code):
        if code not in ERROR_CODES:
            raise ValueError('Unsupported Java cache diagnostic code')
        self.code = code
        super().__init__(code)


def _plain(path, *, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise ValueError('JAVA_DB_UNSAFE_CACHE_PATH')
    return info


def _directories(path):
    for item in reversed((path, *path.parents)):
        _plain(item, directory=True)


def _stamp(info):
    # Reading may update atime; it does not change the physical object/content.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _stage_budget(stage):
    pending, total, entries = [stage], 0, 0
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                if entries > MAX_STAGE_ENTRIES:
                    raise ValueError('JAVA_DB_STAGE_ENTRY_BUDGET')
                item = Path(child.path)
                if child.is_dir(follow_symlinks=False):
                    _plain(item, directory=True)
                    pending.append(item)
                else:
                    total += _plain(item).st_size
                    if total > MAX_STAGE_BYTES:
                        raise ValueError('JAVA_DB_STAGE_BYTE_BUDGET')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('JAVA_DB_DUPLICATE_METADATA')
        result[key] = value
    return result


def _timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError('JAVA_DB_UNSUPPORTED_METADATA_TIME')
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError('JAVA_DB_UNSUPPORTED_METADATA_TIME') from None
    if parsed.utcoffset() is None:
        raise ValueError('JAVA_DB_UNSUPPORTED_METADATA_TIME')
    return parsed


def validate(directory):
    """Read-only, bounded supported-schema validation and actual content hashes."""
    _plain(directory, directory=True)
    entries = set()
    for entry in directory.iterdir():
        if entry.name not in ('trivy-java.db', 'metadata.json'):
            raise ValueError('JAVA_DB_UNEXPECTED_CACHE_ENTRY')
        entries.add(entry.name)
    if entries != {'trivy-java.db', 'metadata.json'}:
        raise ValueError('JAVA_DB_INCOMPLETE_CACHE')
    database, metadata = directory / 'trivy-java.db', directory / 'metadata.json'
    db_info, meta_info = _plain(database), _plain(metadata)
    if not 0 < db_info.st_size <= MAX_DATABASE_BYTES:
        raise ValueError('JAVA_DB_BYTE_BUDGET')
    if not 0 < meta_info.st_size <= MAX_METADATA_BYTES:
        raise ValueError('JAVA_DB_METADATA_BUDGET')
    with database.open('rb') as stream:
        header = stream.read(100)
    page_size = int.from_bytes(header[16:18], 'big')
    page_size = 65536 if page_size == 1 else page_size
    if (len(header) != 100 or header[:16] != b'SQLite format 3\0'
            or page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
            or header[18:20] != b'\x01\x01' or header[24:28] != header[92:96]
            or int.from_bytes(header[28:32], 'big') * page_size != db_info.st_size):
        raise ValueError('JAVA_DB_UNSUPPORTED_FILE_LAYOUT')
    with metadata.open('rb') as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) != meta_info.st_size:
        raise ValueError('JAVA_DB_METADATA_CHANGED')
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('JAVA_DB_UNSUPPORTED_METADATA') from None
    if not isinstance(document, dict) or type(document.get('Version')) is not int or document['Version'] != 1:
        raise ValueError('JAVA_DB_UNSUPPORTED_METADATA_VERSION')
    updated = _timestamp(document.get('UpdatedAt'))
    next_update = _timestamp(document.get('NextUpdate'))
    if next_update <= updated:
        raise ValueError('JAVA_DB_UNSUPPORTED_METADATA_TIME')
    if 'DownloadedAt' in document:
        _timestamp(document['DownloadedAt'])
    from .public_hash_identity import file_sha256
    digest = file_sha256(database)
    with PublicJavaHashLookup(database, digest):
        pass
    # Reject a changed file/path after hashing or schema inspection. This is not
    # a security boundary against a hostile writer sharing the service workspace.
    with metadata.open('rb') as stream:
        unchanged = stream.read(MAX_METADATA_BYTES + 1) == raw
    if (_stamp(_plain(database)) != _stamp(db_info)
            or _stamp(_plain(metadata)) != _stamp(meta_info) or not unchanged):
        raise ValueError('JAVA_DB_CACHE_CHANGED')
    return {'database_sha256': digest,
        'database_bytes': db_info.st_size,
        'database_metadata_sha256': hashlib.sha256(raw).hexdigest(),
        'database_metadata_version': document['Version'],
        'database_updated_at': document['UpdatedAt'],
        'database_next_update': document['NextUpdate'],
        'database_stale': next_update < datetime.now(UTC),
        'database_validation': 'full SHA256; supported read-only SQLite schema/index; not full integrity/authenticity'}


def publish_noreplace(source, destination):
    """Atomic directory visibility without replacing even an empty destination."""
    if os.name == 'nt':
        os.rename(source, destination)  # Windows rejects an existing destination.
        return
    if not sys.platform.startswith('linux'):
        raise OSError('JAVA_DB_ATOMIC_PUBLICATION_UNSUPPORTED')
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, 'renameat2', None)
    if rename is None:
        raise OSError('JAVA_DB_ATOMIC_PUBLICATION_UNSUPPORTED')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        raise OSError(ctypes.get_errno(), 'JAVA_DB_ATOMIC_PUBLICATION_FAILED')


def ensure(cache, downloader):
    """Reuse a valid read-only cache, or perform one isolated staged download."""
    cache = Path(os.path.abspath(cache))
    cache.mkdir(parents=True, exist_ok=True)
    _directories(cache)
    target = cache / 'java-db'
    if os.path.lexists(target):
        return _reuse(target)
    lock = cache / 'java-db-bootstrap.lock'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(lock, flags, 0o600)
    except FileExistsError:
        raise DatabaseCacheError('BOOTSTRAP_BUSY') from None
    owned = os.fstat(descriptor)
    try:
        # Another cooperating process may have published before this lock.
        if os.path.lexists(target):
            return _reuse(target)
        with tempfile.TemporaryDirectory(prefix='.java-db-bootstrap-', dir=cache) as temporary:
            stage = Path(temporary)
            _directories(stage)
            started = time.monotonic()
            try:
                downloader(stage)
            except (OSError, ValueError, RuntimeError):
                raise DatabaseCacheError('DOWNLOAD_FAILED') from None
            download_seconds = time.monotonic() - started
            started = time.monotonic()
            try:
                _stage_budget(stage)
                facts = validate(stage / 'java-db')
            except (OSError, ValueError, sqlite3.Error):
                raise DatabaseCacheError('DOWNLOAD_INVALID') from None
            _directories(cache)
            try:
                publish_noreplace(stage / 'java-db', target)
            except OSError:
                raise DatabaseCacheError('PUBLICATION_FAILED') from None
            return {**facts, 'java_database_cache_status': 'published',
                    'java_database_cache_publication': 'atomic-directory-no-replace',
                    'java_database_download_seconds': download_seconds,
                    'java_database_validation_seconds': time.monotonic() - started}
    finally:
        os.close(descriptor)
        # Never unlink an unrelated replacement or a lock left by another job.
        try:
            current = lock.lstat()
        except FileNotFoundError:
            current = None
        if current is not None and (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
            lock.unlink()


def _reuse(target):
    started = time.monotonic()
    try:
        facts = validate(target)
    except (OSError, ValueError, sqlite3.Error):
        raise DatabaseCacheError('CACHE_INVALID') from None
    return {**facts, 'java_database_cache_status': 'reused',
            'java_database_cache_publication': 'existing validated directory; no refresh',
            'java_database_download_seconds': 0.0,
            'java_database_validation_seconds': time.monotonic() - started}

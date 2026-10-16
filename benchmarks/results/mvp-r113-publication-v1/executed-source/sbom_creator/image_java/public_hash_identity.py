"""Exact SHA-1 lookup in a pinned public Trivy Java DB snapshot.

This is an index association, not publisher authentication or global GAV
uniqueness. The caller must hash complete physical archive bytes, preserve a
separate SHA256, and independently bind the returned GAV to the image/path/layer.
No filename, project, manifest, build cache, reference, network, or fallback input.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from pathlib import Path

from packageurl import PackageURL

MAX_DATABASE_BYTES = 2 * 1024**3
MAX_FIELD = 512
MAX_LOOKUPS = 4096
QUERY = '''SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type
FROM indices i JOIN artifacts a ON a.id = i.artifact_id
WHERE i.sha1 = ? LIMIT 2'''
HEX40 = re.compile(r'[a-fA-F0-9]{40}')
HEX64 = re.compile(r'[a-f0-9]{64}')


def file_sha256(path):
    digest, size = hashlib.sha256(), 0
    with Path(path).open('rb') as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > MAX_DATABASE_BYTES:
                raise ValueError('Public database byte budget')
            digest.update(block)
    return digest.hexdigest()


class PublicJavaHashLookup:
    """One read-only connection and bounded indexed queries, closed by its caller."""

    def __init__(self, database, expected_sha256):
        database = Path(database).resolve(strict=True)
        if (not HEX64.fullmatch(expected_sha256) or not database.is_file()
                or database.stat().st_size > MAX_DATABASE_BYTES
                or file_sha256(database) != expected_sha256):
            raise ValueError('Public database snapshot does not match the pinned SHA256')
        with database.open('rb') as stream:
            if stream.read(16) != b'SQLite format 3\0':
                raise ValueError('Expected the public SQLite Java DB format')
        self.database, self.sha256 = database, expected_sha256
        self.connection = sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1',
                                          uri=True, timeout=1.0)
        try:
            started, callbacks = time.monotonic(), 0

            def bounded_schema():
                nonlocal callbacks
                callbacks += 1
                return int(callbacks > 100 or time.monotonic() - started > 2.0)

            self.connection.set_progress_handler(bounded_schema, 1000)
            self.connection.execute('PRAGMA query_only=ON')
            self.connection.execute('PRAGMA trusted_schema=OFF')
            self.connection.execute('PRAGMA mmap_size=0')
            self.connection.execute('PRAGMA cache_size=-8192')
            details = {table: self.connection.execute('PRAGMA table_info(' + table + ')').fetchall()
                       for table in ('artifacts', 'indices')}
            columns = {table: [(row[1], row[2]) for row in rows] for table, rows in details.items()}
            expected = {'artifacts': [('id', 'INTEGER'), ('group_id', 'TEXT'), ('artifact_id', 'TEXT')],
                        'indices': [('artifact_id', 'INTEGER'), ('version', 'TEXT'),
                                    ('sha1', 'BLOB'), ('archive_type', 'TEXT')]}
            if columns != expected:
                raise ValueError('Unsupported public Java DB schema')
            if [row[1] for row in details['artifacts'] if row[5]] != ['id']:
                raise ValueError('Unsupported public Java DB primary-key schema')
            indexes = self.connection.execute('PRAGMA index_list(indices)').fetchall()
            index_columns = self.connection.execute('PRAGMA index_info(indices_sha1_idx)').fetchall()
            if (not any(row[1] == 'indices_sha1_idx' and row[2] == 1 and row[4] == 0 for row in indexes)
                    or [row[2] for row in index_columns] != ['sha1']):
                raise ValueError('Expected exact SHA1 unique index is absent')
            self.query_plan = self.connection.execute('EXPLAIN QUERY PLAN ' + QUERY, (b'\0' * 20,)).fetchall()
            if (not any('indices_sha1_idx' in row[3] for row in self.query_plan)
                    or not any('SEARCH a USING INTEGER PRIMARY KEY' in row[3] for row in self.query_plan)):
                raise ValueError('Exact hash lookup would not use the expected bounded index')
            self.schema = columns
            self.lookups = 0
            self.connection.set_progress_handler(None, 0)
        except BaseException:
            self.close()
            raise

    def lookup(self, sha1):
        if self.connection is None:
            raise ValueError('Closed public hash lookup')
        if not isinstance(sha1, str) or not HEX40.fullmatch(sha1):
            raise ValueError('Complete hexadecimal SHA1 digest is required')
        if self.lookups >= MAX_LOOKUPS:
            raise ValueError('Per-connection hash lookup budget')
        self.lookups += 1
        started, callbacks = time.monotonic(), 0

        def bounded_query():
            nonlocal callbacks
            callbacks += 1
            return int(callbacks > 100 or time.monotonic() - started > 1.0)

        self.connection.set_progress_handler(bounded_query, 1000)
        try:
            rows = self.connection.execute(QUERY, (sqlite3.Binary(bytes.fromhex(sha1)),)).fetchall()
        finally:
            self.connection.set_progress_handler(None, 0)
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError('Ambiguous public hash index result')
        group, artifact, version, stored_sha1, archive_type = rows[0]
        if (stored_sha1 != bytes.fromhex(sha1) or archive_type != 'jar'
                or any(not isinstance(value, str) or not value or len(value) > MAX_FIELD
                       or value.strip() != value or any(ord(char) < 32 for char in value)
                       for value in (group, artifact, version))):
            raise ValueError('Unsupported or inconsistent public hash association')
        return {'purl': PackageURL(type='maven', namespace=group, name=artifact, version=version).to_string(),
                'group': group, 'artifact': artifact, 'version': version,
                'sha1': sha1.lower(), 'archive_type': archive_type,
                'database_sha256': self.sha256,
                'lookup': 'exact_full_archive_sha1_blob',
                'publisher_authenticated': False,
                'globally_unique_gav_proven': False}

    def verify_unchanged(self):
        if file_sha256(self.database) != self.sha256:
            raise ValueError('Public Java database changed during archive verification')

    def close(self):
        if getattr(self, 'connection', None) is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

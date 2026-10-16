"""Public index lookup uses real SQLite files, binary keys and read-only access."""
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from sbom_creator.image_java import public_hash_identity as public

SHA1 = '0123456789abcdef0123456789abcdef01234567'
OTHER_SHA1 = '0000000000000000000000000000000000000000'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def database(path, *, index='unique', sha1=None, archive='jar', group='org.example',
             artifact='sample-artifact', version='1.2.3', malformed_schema=False):
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)')
        connection.execute('CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT, '
                           'foreign key (artifact_id) references artifacts(id))')
        connection.execute('CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id, group_id)')
        connection.execute('CREATE INDEX indices_artifact_idx ON indices(artifact_id)')
        if index == 'unique':
            connection.execute('CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1)')
        elif index == 'nonunique':
            connection.execute('CREATE INDEX indices_sha1_idx ON indices(sha1)')
        elif index == 'wrong-column':
            connection.execute('CREATE UNIQUE INDEX indices_sha1_idx ON indices(version)')
        connection.execute('INSERT INTO artifacts VALUES(1,?,?)', (group, artifact))
        connection.execute('INSERT INTO indices VALUES(1,?,?,?)',
                           (version, bytes.fromhex(SHA1) if sha1 is None else sha1, archive))
        if malformed_schema:
            connection.execute('ALTER TABLE indices ADD COLUMN extra_sha256 TEXT')
    return path


@pytest.fixture
def pinned_database(tmp_path):
    path = database(tmp_path / 'public.db')
    return path, digest(path)


def test_exact_complete_binary_hash_returns_index_association(pinned_database):
    path, pin = pinned_database
    with public.PublicJavaHashLookup(path, pin) as lookup:
        result = lookup.lookup(SHA1.upper())
        assert result['purl'] == 'pkg:maven/org.example/sample-artifact@1.2.3'
        assert result['sha1'] == SHA1
        assert result['database_sha256'] == pin
        assert result['archive_type'] == 'jar'
        assert not result['publisher_authenticated']
        assert not result['globally_unique_gav_proven']
        assert any('indices_sha1_idx' in step[3] for step in lookup.query_plan)
        lookup.verify_unchanged()


def test_absent_hash_has_no_name_or_version_fallback(pinned_database):
    path, pin = pinned_database
    with public.PublicJavaHashLookup(path, pin) as lookup:
        assert lookup.lookup(OTHER_SHA1) is None


@pytest.mark.parametrize('value', [SHA1[:-1], SHA1 + '0', 'g' * 40,
                                 'sample-artifact-1.2.3.jar', 'sha1:' + SHA1, None])
def test_only_complete_hex_hashes_are_accepted(pinned_database, value):
    path, pin = pinned_database
    with public.PublicJavaHashLookup(path, pin) as lookup, pytest.raises(ValueError, match='Complete hexadecimal'):
        lookup.lookup(value)


def test_sqlite_text_key_is_not_mistaken_for_binary_digest(tmp_path):
    path = database(tmp_path / 'text-key.db', sha1=SHA1)
    with public.PublicJavaHashLookup(path, digest(path)) as lookup:
        assert lookup.lookup(SHA1) is None


def test_wrong_database_hash_fails_before_query(pinned_database):
    path, _ = pinned_database
    with pytest.raises(ValueError, match='snapshot'):
        public.PublicJavaHashLookup(path, '0' * 64)


def test_matching_hash_of_non_sqlite_file_is_still_rejected(tmp_path):
    path = tmp_path / 'not-a-db'
    path.write_bytes(b'A matching pin does not establish a supported database format')
    with pytest.raises(ValueError, match='SQLite'):
        public.PublicJavaHashLookup(path, digest(path))


def test_database_size_bound(pinned_database, monkeypatch):
    path, pin = pinned_database
    monkeypatch.setattr(public, 'MAX_DATABASE_BYTES', path.stat().st_size - 1)
    with pytest.raises(ValueError, match='snapshot'):
        public.PublicJavaHashLookup(path, pin)


@pytest.mark.parametrize('index', ['missing', 'nonunique', 'wrong-column'])
def test_exact_unique_hash_index_is_mandatory(tmp_path, index):
    path = database(tmp_path / 'unsupported-index.db', index=index)
    with pytest.raises(ValueError, match='unique index'):
        public.PublicJavaHashLookup(path, digest(path))


def test_schema_change_is_not_silently_accepted(tmp_path):
    path = database(tmp_path / 'future-schema.db', malformed_schema=True)
    with pytest.raises(ValueError, match='schema'):
        public.PublicJavaHashLookup(path, digest(path))


@pytest.mark.parametrize('kwargs', [{'archive': 'aar'}, {'group': ''}, {'artifact': 'bad\nname'},
                                    {'version': ' padded '}, {'version': 'x' * 513}])
def test_wrong_archive_or_invalid_gav_is_not_promoted(tmp_path, kwargs):
    path = database(tmp_path / 'unsupported-row.db', **kwargs)
    with public.PublicJavaHashLookup(path, digest(path)) as lookup, pytest.raises(ValueError, match='association'):
        lookup.lookup(SHA1)


def test_connection_is_actually_read_only_and_closed_after_context(pinned_database):
    path, pin = pinned_database
    with public.PublicJavaHashLookup(path, pin) as lookup:
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            lookup.connection.execute("INSERT INTO artifacts VALUES(2,'bad','write')")
        assert lookup.lookup(SHA1)['artifact'] == 'sample-artifact'
    assert digest(path) == pin
    with pytest.raises(ValueError, match='Closed'):
        lookup.lookup(SHA1)
    lookup.close()  # Repeated cleanup is harmless.


def test_mutated_snapshot_is_detected(pinned_database):
    path, pin = pinned_database
    with public.PublicJavaHashLookup(path, pin) as lookup:
        with sqlite3.connect(path) as writer:
            writer.execute("INSERT INTO artifacts VALUES(2,'org.other','changed')")
        with pytest.raises(ValueError, match='changed during'):
            lookup.verify_unchanged()


def test_per_connection_query_budget_is_enforced(pinned_database, monkeypatch):
    path, pin = pinned_database
    monkeypatch.setattr(public, 'MAX_LOOKUPS', 2)
    with public.PublicJavaHashLookup(path, pin) as lookup:
        assert lookup.lookup(SHA1)
        assert lookup.lookup(OTHER_SHA1) is None
        with pytest.raises(ValueError, match='lookup budget'):
            lookup.lookup(SHA1)


SLOW_QUERY = '''WITH RECURSIVE n(x) AS
(SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<10000000)
SELECT a.group_id,a.artifact_id,i.version,i.sha1,i.archive_type
FROM indices i JOIN artifacts a ON a.id=i.artifact_id JOIN n
WHERE i.sha1=? ORDER BY n.x DESC LIMIT 2'''


@pytest.mark.parametrize('wall_deadline', [False, True])
def test_real_sqlite_query_is_interrupted_and_handler_is_removed(pinned_database, monkeypatch, wall_deadline):
    path, pin = pinned_database
    with public.PublicJavaHashLookup(path, pin) as lookup:
        fixed_query = public.QUERY
        monkeypatch.setattr(public, 'QUERY', SLOW_QUERY)
        ticks = iter([0.0, 2.0])
        monkeypatch.setattr(public, 'time', SimpleNamespace(monotonic=(
            (lambda: next(ticks, 2.0)) if wall_deadline else lambda: 0.0)))
        with pytest.raises(sqlite3.OperationalError, match='interrupted'):
            lookup.lookup(SHA1)
        monkeypatch.setattr(public, 'QUERY', fixed_query)
        assert lookup.lookup(SHA1)['artifact'] == 'sample-artifact'

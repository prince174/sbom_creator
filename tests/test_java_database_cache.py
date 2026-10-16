"""Cold cache publication is bounded/atomic; existing snapshots are read-only."""
import copy
import hashlib
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from test_public_java_hash_identity import database

from sbom_creator.image_java import java_database_cache as cache_module

META = {'Version': 1, 'UpdatedAt': '2020-01-01T00:00:00Z', 'NextUpdate': '2099-01-01T00:00:00Z'}
VALIDATION_ERRORS = (ValueError, sqlite3.Error)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def populate(cache, metadata=None, *, schema=False):
    target = cache / 'java-db'
    target.mkdir(parents=True)
    db = database(target / 'trivy-java.db', malformed_schema=schema)
    (target / 'metadata.json').write_text(json.dumps(META if metadata is None else metadata), encoding='utf-8')
    return db


def files_below(cache):
    return {p.relative_to(cache).as_posix(): sha(p) for p in cache.rglob('*') if p.is_file()}


def forbidden(*args):
    raise AssertionError('A warm or invalid existing target must never download or refresh')


def test_cold_download_uses_private_stage_then_publishes_both_validated_files(tmp_path):
    cache = tmp_path / 'cache'
    stages = []

    def download(stage):
        stages.append(stage)
        assert stage != cache
        assert not (cache / 'java-db').exists()
        populate(stage)

    fingerprint = cache_module.ensure(cache, download)
    target = cache / 'java-db'
    assert len(stages) == 1
    assert not stages[0].exists()
    assert {p.name for p in target.iterdir()} == {'trivy-java.db', 'metadata.json'}
    assert fingerprint['database_sha256'] == sha(target / 'trivy-java.db')
    assert fingerprint['database_metadata_sha256'] == sha(target / 'metadata.json')
    assert fingerprint['database_bytes'] == (target / 'trivy-java.db').stat().st_size
    assert fingerprint['database_metadata_version'] == 1
    assert fingerprint['database_stale'] is False
    assert fingerprint['java_database_cache_status'] == 'published'
    assert fingerprint['java_database_cache_publication'] == 'atomic-directory-no-replace'
    assert not (cache / 'java-db-bootstrap.lock').exists()


def test_valid_warm_cache_is_reused_without_staging_network_or_mutation(tmp_path, monkeypatch):
    cache = tmp_path / 'cache'
    populate(cache)
    before = files_below(cache)
    monkeypatch.setattr(cache_module.tempfile, 'TemporaryDirectory', forbidden)
    result = cache_module.ensure(cache, forbidden)
    assert result['java_database_cache_status'] == 'reused'
    assert result['database_sha256'] == before['java-db/trivy-java.db']
    assert files_below(cache) == before


def test_stale_snapshot_is_explicitly_reused_offline_not_refreshed(tmp_path):
    cache = tmp_path / 'cache'
    metadata = {**META, 'NextUpdate': '2020-01-02T00:00:00Z'}
    populate(cache, metadata)
    before = files_below(cache)
    result = cache_module.ensure(cache, forbidden)
    assert result['database_stale'] is True
    assert result['java_database_cache_status'] == 'reused'
    assert files_below(cache) == before


@pytest.mark.parametrize('optional', [False, True])
def test_downloaded_at_is_optional_but_supported_when_present(tmp_path, optional):
    cache = tmp_path / 'cache'
    metadata = copy.deepcopy(META)
    if optional:
        metadata['DownloadedAt'] = '2020-01-01T01:02:03.123456789Z'
    populate(cache, metadata)
    assert cache_module.ensure(cache, forbidden)['database_metadata_version'] == 1


@pytest.mark.parametrize('failure', [RuntimeError, TimeoutError])
def test_failed_partial_download_does_not_poison_target_or_retry_itself(tmp_path, failure):
    cache = tmp_path / 'cache'
    calls = []

    def partial(stage):
        calls.append(stage)
        target = stage / 'java-db'
        target.mkdir()
        (target / 'trivy-java.db').write_bytes(b'incomplete download')
        raise failure('synthetic downloader failure')

    with pytest.raises((RuntimeError, TimeoutError, ValueError)):
        cache_module.ensure(cache, partial)
    assert len(calls) == 1
    assert not (cache / 'java-db').exists()
    assert not calls[0].exists()
    assert not (cache / 'java-db-bootstrap.lock').exists()
    result = cache_module.ensure(cache, populate)
    assert result['java_database_cache_status'] == 'published'


@pytest.mark.parametrize('kind', ['empty', 'partial-db', 'db-only', 'metadata-only', 'malformed-sqlite', 'wrong-schema'])
def test_existing_invalid_target_is_preserved_and_never_overwritten(tmp_path, kind):
    cache = tmp_path / 'cache'
    target = cache / 'java-db'
    if kind in ('empty', 'partial-db', 'db-only', 'metadata-only', 'malformed-sqlite'):
        target.mkdir(parents=True)
        if kind in ('partial-db', 'malformed-sqlite'):
            body = b'partial' if kind == 'partial-db' else b'SQLite format 3\0' + bytes(256)
            (target / 'trivy-java.db').write_bytes(body)
        elif kind == 'db-only':
            database(target / 'trivy-java.db')
        if kind in ('metadata-only', 'malformed-sqlite'):
            (target / 'metadata.json').write_text(json.dumps(META), encoding='utf-8')
    else:
        populate(cache, schema=True)
    before = files_below(cache)
    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, forbidden)
    assert target.is_dir()
    assert files_below(cache) == before


def test_existing_target_file_is_preserved_not_interpreted_as_absent(tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / 'java-db').write_bytes(b'preserve me')
    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, forbidden)
    assert (cache / 'java-db').read_bytes() == b'preserve me'


@pytest.mark.parametrize('metadata', [
    {}, {'Version': 1}, {**META, 'Version': True}, {**META, 'Version': 2},
    {**META, 'Version': '1'}, {**META, 'UpdatedAt': '2020-01-01'},
    {**META, 'NextUpdate': 'no timestamp'}, {**META, 'NextUpdate': '2020-01-01T00:00:00'},
    {**META, 'DownloadedAt': None}, {**META, 'DownloadedAt': 'not a date'},
])
def test_invalid_metadata_never_becomes_a_published_cache(tmp_path, metadata):
    cache = tmp_path / 'cache'
    stage_paths = []

    def invalid(stage):
        stage_paths.append(stage)
        populate(stage, metadata)

    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, invalid)
    assert not (cache / 'java-db').exists()
    assert not stage_paths[0].exists()


@pytest.mark.parametrize('raw', [
    b'[]', b'null', b'{',
    b'{"Version":1,"Version":1,"UpdatedAt":"2020-01-01T00:00:00Z","NextUpdate":"2099-01-01T00:00:00Z"}',
    b'{"Version":1,"UpdatedAt":"2020-01-01T00:00:00Z","NextUpdate":"2099-01-01T00:00:00Z","padding":"' + b'x' * 16384 + b'"}',
], ids=['array', 'null', 'invalid-json', 'duplicate-key', 'metadata-budget'])
def test_metadata_shape_duplicates_and_byte_budget_fail_before_publication(tmp_path, raw):
    cache = tmp_path / 'cache'

    def invalid(stage):
        populate(stage)
        (stage / 'java-db/metadata.json').write_bytes(raw)

    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, invalid)
    assert not (cache / 'java-db').exists()


@pytest.mark.parametrize('mutation', ['trailing-byte', 'truncate-page', 'bad-header'])
def test_inconsistent_sqlite_file_shape_does_not_publish(tmp_path, mutation):
    cache = tmp_path / 'cache'

    def invalid(stage):
        db = populate(stage)
        body = db.read_bytes()
        if mutation == 'trailing-byte':
            db.write_bytes(body + b'x')
        elif mutation == 'truncate-page':
            db.write_bytes(body[:-4096])
        else:
            db.write_bytes(b'not SQLite data' + body[15:])

    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, invalid)
    assert not (cache / 'java-db').exists()


@pytest.mark.parametrize('name', ['trivy-java.db-wal', 'trivy-java.db-journal', 'unexpected-data.txt'])
def test_unexpected_data_in_snapshot_is_not_published(tmp_path, name):
    cache = tmp_path / 'cache'

    def invalid(stage):
        populate(stage)
        (stage / 'java-db' / name).write_bytes(b'extra bytes')

    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, invalid)
    assert not (cache / 'java-db').exists()


def test_database_size_budget_rejects_before_hashing_without_big_allocation(tmp_path, monkeypatch):
    cache = tmp_path / 'cache'
    db = populate(cache)
    monkeypatch.setattr(cache_module, 'MAX_DATABASE_BYTES', db.stat().st_size - 1)
    before = files_below(cache)
    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, forbidden)
    assert files_below(cache) == before


@pytest.mark.parametrize('changed', ['metadata', 'database'])
def test_mutation_during_schema_validation_is_not_published(tmp_path, monkeypatch, changed):
    cache = tmp_path / 'cache'
    original = cache_module.PublicJavaHashLookup

    @contextmanager
    def changing(database_path, pin):
        with original(database_path, pin) as lookup:
            pass
        # Inject after the genuine read-only schema check closes its connection,
        # avoiding platform-specific file-sharing restrictions in this test.
        if changed == 'metadata':
            database_path.with_name('metadata.json').write_text(
                json.dumps({**META, 'DownloadedAt': '2020-01-02T00:00:00Z'}), encoding='utf-8')
        else:
            database_path.write_bytes(database_path.read_bytes() + b'x')
        yield lookup

    monkeypatch.setattr(cache_module, 'PublicJavaHashLookup', changing)
    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, populate)
    assert not (cache / 'java-db').exists()


def make_symlink(source, target, *, directory=False):
    try:
        os.symlink(source, target, target_is_directory=directory)
    except OSError as error:
        pytest.skip('Native symlink creation unavailable: ' + type(error).__name__)


@pytest.mark.parametrize('location', ['cache-root', 'java-db', 'trivy-java.db', 'metadata.json'])
def test_existing_symlinks_are_preserved_rejected_and_never_followed_for_download(tmp_path, location):
    outside = tmp_path / 'outside'
    populate(outside)
    cache = tmp_path / 'cache'
    if location == 'cache-root':
        make_symlink(outside, cache, directory=True)
    elif location == 'java-db':
        cache.mkdir()
        make_symlink(outside / 'java-db', cache / 'java-db', directory=True)
    else:
        populate(cache)
        item = cache / 'java-db' / location
        item.unlink()
        make_symlink(outside / 'java-db' / location, item)
    before = files_below(outside)
    with pytest.raises((*VALIDATION_ERRORS, OSError)):
        cache_module.ensure(cache, forbidden)
    assert files_below(outside) == before


@pytest.mark.parametrize('location', ['trivy-java.db', 'metadata.json'])
def test_hardlinked_snapshot_files_are_not_accepted(tmp_path, location):
    cache = tmp_path / 'cache'
    populate(cache)
    item = cache / 'java-db' / location
    alias = tmp_path / ('alias-' + location)
    os.link(item, alias)
    before = item.read_bytes()
    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, forbidden)
    assert item.read_bytes() == before == alias.read_bytes()


def test_failed_staged_symlink_validation_does_not_delete_link_target(tmp_path):
    cache = tmp_path / 'cache'
    outside = tmp_path / 'outside'
    populate(outside)
    before = files_below(outside)

    def linked(stage):
        make_symlink(outside / 'java-db', stage / 'java-db', directory=True)

    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, linked)
    assert files_below(outside) == before
    assert not (cache / 'java-db').exists()


def test_linked_ancestor_is_rejected_before_creating_a_new_cache_child(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    sentinel = outside / 'sentinel'
    sentinel.write_bytes(b'preserve outside directory')
    link = tmp_path / 'linked-parent'
    make_symlink(outside, link, directory=True)
    with pytest.raises((*VALIDATION_ERRORS, OSError)):
        cache_module.ensure(link / 'new-child' / 'cache', forbidden)
    assert not (outside / 'new-child').exists()
    assert sentinel.read_bytes() == b'preserve outside directory'


def test_preexisting_bootstrap_lock_is_not_removed_or_retried(tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    lock = cache / 'java-db-bootstrap.lock'
    lock.write_bytes(b'owned by another job')
    with pytest.raises(VALIDATION_ERRORS):
        cache_module.ensure(cache, forbidden)
    assert lock.read_bytes() == b'owned by another job'
    assert not (cache / 'java-db').exists()


def test_valid_warm_cache_does_not_need_or_remove_a_foreign_bootstrap_lock(tmp_path):
    cache = tmp_path / 'cache'
    populate(cache)
    lock = cache / 'java-db-bootstrap.lock'
    lock.write_bytes(b'foreign lock retained')
    result = cache_module.ensure(cache, forbidden)
    assert result['java_database_cache_status'] == 'reused'
    assert lock.read_bytes() == b'foreign lock retained'


def test_owned_cleanup_does_not_remove_an_unrelated_abandoned_stage(tmp_path):
    cache = tmp_path / 'cache'
    orphan = cache / '.java-db-bootstrap-old'
    orphan.mkdir(parents=True)
    sentinel = orphan / 'unowned-data'
    sentinel.write_bytes(b'do not clean another attempt')
    assert cache_module.ensure(cache, populate)['java_database_cache_status'] == 'published'
    assert sentinel.read_bytes() == b'do not clean another attempt'


@pytest.mark.parametrize('nonempty', [False, True])
def test_target_created_at_publication_race_is_never_replaced(tmp_path, monkeypatch, nonempty):
    cache = tmp_path / 'cache'
    original = cache_module.publish_noreplace
    observed = []

    def raced(source, target):
        target.mkdir()
        if nonempty:
            (target / 'sentinel').write_bytes(b'existing target')
        observed.append(target.stat().st_ino)
        original(source, target)

    monkeypatch.setattr(cache_module, 'publish_noreplace', raced)
    with pytest.raises((ValueError, OSError)):
        cache_module.ensure(cache, populate)
    target = cache / 'java-db'
    assert target.stat().st_ino == observed[0]
    assert {p.name for p in target.iterdir()} == ({'sentinel'} if nonempty else set())
    assert not (cache / 'java-db-bootstrap.lock').exists()


def test_concurrent_cooperating_cold_call_fails_busy_without_second_download(tmp_path):
    cache = tmp_path / 'cache'
    ready, release = threading.Event(), threading.Event()
    calls = []

    def slow(stage):
        calls.append(stage)
        populate(stage)
        ready.set()
        assert release.wait(5), 'The test must release the owned downloader'

    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(cache_module.ensure, cache, slow)
        try:
            assert ready.wait(5)
            with pytest.raises(VALIDATION_ERRORS):
                cache_module.ensure(cache, forbidden)
            assert not (cache / 'java-db').exists()
            assert len(calls) == 1
        finally:
            release.set()
        assert pending.result(timeout=5)['java_database_cache_status'] == 'published'


@pytest.mark.parametrize('kind', ['single-extra-bytes', 'aggregate-extra-bytes', 'entry-count'])
def test_whole_download_stage_is_budgeted_even_outside_valid_java_db_pair(tmp_path, monkeypatch, kind):
    cache = tmp_path / 'cache'
    stages = []

    def download(stage):
        stages.append(stage)
        populate(stage)
        pair_bytes = sum(p.stat().st_size for p in (stage / 'java-db').iterdir())
        if kind == 'single-extra-bytes':
            monkeypatch.setattr(cache_module, 'MAX_STAGE_BYTES', pair_bytes + 7)
            (stage / 'unrelated-download-data').write_bytes(b'x' * 8)
        elif kind == 'aggregate-extra-bytes':
            monkeypatch.setattr(cache_module, 'MAX_STAGE_BYTES', pair_bytes + 15)
            for number in range(2):
                (stage / f'unrelated-{number}').write_bytes(b'x' * 8)
        else:
            monkeypatch.setattr(cache_module, 'MAX_STAGE_ENTRIES', 4)
            # The valid pair plus its directory uses three entries; two unrelated
            # empty files exceed entry count without consuming a byte budget.
            for number in range(2):
                (stage / f'unrelated-{number}').write_bytes(b'')

    with pytest.raises(cache_module.DatabaseCacheError) as error:
        cache_module.ensure(cache, download)
    assert error.value.code == 'DOWNLOAD_INVALID'
    assert not (cache / 'java-db').exists()
    assert not stages[0].exists()
    assert not (cache / 'java-db-bootstrap.lock').exists()


@pytest.mark.parametrize('invalid', ['CACHE_INVALID/private-path', 'metadata-secret', '', None, 1])
def test_cache_error_constructor_only_accepts_fixed_internal_codes(invalid):
    with pytest.raises(ValueError):
        cache_module.DatabaseCacheError(invalid)


@pytest.mark.parametrize('code', sorted(cache_module.ERROR_CODES))
def test_scanner_only_exports_fixed_cache_code_never_exception_content(tmp_path, monkeypatch, code):
    from sbom_creator import scanner
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java import runtime

    raw = {'artifacts': [{'id': 'java', 'foundBy': 'java-archive-cataloger'}], 'files': []}
    monkeypatch.setattr(scanner, '_syft', lambda *args, **kwargs: copy.deepcopy(raw))
    monkeypatch.setattr(scanner, '_image_identity', lambda *args: {
        'immutable_reference': 'example.com/app@sha256:' + 'a' * 64})
    monkeypatch.setattr(scanner, 'collect_payload', lambda *args: {'java': {'status': 'unconfirmed', 'path': None}})
    error = cache_module.DatabaseCacheError(code)
    error.args = ('private-cache-path/metadata-secret must never be exported',)

    def fail(*args):
        raise error

    monkeypatch.setattr(runtime, 'analyze', fail)
    document, provenance = scanner.scan_image('example.com/app@sha256:' + 'a' * 64,
                                              tmp_path / 'image.json', Settings(registry_hosts=('example.com',)))
    assert document == raw
    assert provenance['java_image_status'] == 'UNKNOWN'
    assert provenance['java_image_error_type'] == 'DatabaseCacheError'
    assert provenance['java_database_cache_error_code'] == code
    assert 'private-cache-path' not in json.dumps(provenance)
    assert 'metadata-secret' not in json.dumps(provenance)


def test_scanner_rejects_mutated_nonconstant_cache_code(tmp_path, monkeypatch):
    from sbom_creator import scanner
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java import runtime

    raw = {'artifacts': [{'id': 'java', 'foundBy': 'java-archive-cataloger'}], 'files': []}
    monkeypatch.setattr(scanner, '_syft', lambda *args, **kwargs: copy.deepcopy(raw))
    monkeypatch.setattr(scanner, '_image_identity', lambda *args: {
        'immutable_reference': 'example.com/app@sha256:' + 'a' * 64})
    monkeypatch.setattr(scanner, 'collect_payload', lambda *args: {})
    error = cache_module.DatabaseCacheError('CACHE_INVALID')
    error.code = 'private-cache-path/metadata-secret'

    def fail(*args):
        raise error

    monkeypatch.setattr(runtime, 'analyze', fail)
    _, provenance = scanner.scan_image('example.com/app@sha256:' + 'a' * 64,
                                       tmp_path / 'image.json', Settings(registry_hosts=('example.com',)))
    assert provenance['java_image_status'] == 'UNKNOWN'
    assert 'java_database_cache_error_code' not in provenance
    assert 'metadata-secret' not in json.dumps(provenance)

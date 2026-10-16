"""The peer adapter must use the cache manager before creation or tool calls."""
import hashlib
import json
import os

import pytest
from test_public_java_hash_identity import database

from sbom_creator.acquire import Settings
from sbom_creator.image_java import runtime
from sbom_creator.image_java.java_database_cache import DatabaseCacheError


def test_cache_preflight_rejection_happens_before_any_tool_or_downloader(tmp_path, monkeypatch):
    root = tmp_path / 'runtime'
    root.mkdir()
    cache = tmp_path / 'uncreated-parent' / 'new-child' / 'cache'
    checked = []

    def reject(path):
        checked.append(path)
        raise ValueError('JAVA_DB_UNSAFE_CACHE_PATH')

    def forbidden(*args, **kwargs):
        raise AssertionError('Rejected cache path must not invoke a tool or downloader')

    monkeypatch.setattr(runtime, 'prepare_cache', reject)
    monkeypatch.setattr(runtime, 'run_command', forbidden)
    monkeypatch.setattr(runtime, 'ensure_database', forbidden)
    with pytest.raises(DatabaseCacheError, match='CACHE_INVALID'):
        runtime.peer(tmp_path / 'input.tar', Settings(trivy_cache_dir=str(cache)), root)
    assert checked == [cache]
    assert not (tmp_path / 'uncreated-parent').exists()


def test_actual_linked_parent_cannot_create_a_child_before_peer_rejects(tmp_path, monkeypatch):
    outside = tmp_path / 'outside'
    outside.mkdir()
    link = tmp_path / 'linked-parent'
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as error:
        pytest.skip('Native symlink creation unavailable: ' + type(error).__name__)
    root = tmp_path / 'runtime'
    root.mkdir()

    def forbidden(*args, **kwargs):
        raise AssertionError('Unsafe path must fail before Trivy or downloader invocation')

    monkeypatch.setattr(runtime, 'run_command', forbidden)
    with pytest.raises(DatabaseCacheError, match='CACHE_INVALID'):
        runtime.peer(tmp_path / 'input.tar', Settings(trivy_cache_dir=str(link / 'new-child' / 'cache')), root)
    assert not (outside / 'new-child').exists()
    assert list(outside.iterdir()) == []


def test_relative_cache_is_the_same_absolute_path_for_staging_and_offline_peer(tmp_path, monkeypatch):
    service = tmp_path / 'service'
    service.mkdir()
    root = tmp_path / 'different-runtime-cwd'
    root.mkdir()
    monkeypatch.chdir(service)
    expected = service / 'data' / 'trivy'
    calls, downloads = [], []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        assert kwargs['cwd'] == root
        if args[1] == 'version':
            return json.dumps({'Version': '0.75.0'})
        cache_path = type(expected)(args[args.index('--cache-dir') + 1])
        assert cache_path.is_absolute()
        if '--download-java-db-only' in args:
            downloads.append(cache_path)
            assert cache_path != expected
            assert cache_path.parent == expected
            target = cache_path / 'java-db'
            target.mkdir()
            database(target / 'trivy-java.db')
            (target / 'metadata.json').write_text(json.dumps({
                'Version': 1, 'UpdatedAt': '2020-01-01T00:00:00Z',
                'NextUpdate': '2099-01-01T00:00:00Z'}), encoding='utf-8')
            return ''
        assert cache_path == expected
        assert '--offline-scan' in args and '--skip-java-db-update' in args
        return json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': []})

    monkeypatch.setattr(runtime, 'run_command', fake_run)
    settings = Settings(trivy_cache_dir='data/trivy')
    _, first = runtime.peer(tmp_path / 'input.tar', settings, root)
    _, second = runtime.peer(tmp_path / 'input.tar', settings, root)
    assert len(downloads) == 1
    assert first['java_database_cache_status'] == 'published'
    assert second['java_database_cache_status'] == 'reused'
    assert first['database_sha256'] == second['database_sha256'] == hashlib.sha256(
        (expected / 'java-db/trivy-java.db').read_bytes()).hexdigest()
    assert not (root / 'data').exists()
    assert len([args for args, _ in calls if '--input' in args]) == 2

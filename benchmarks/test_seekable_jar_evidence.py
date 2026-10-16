import hashlib
import io
import tarfile
import zipfile
from unittest.mock import patch

import pytest
import seekable_jar_evidence as candidate
from test_bounded_jar_evidence import artifact, jar
from test_seekable_layer_index import fixture


def reader(tmp_path, data):
    path, digest = fixture(tmp_path, [('app.jar', data, tarfile.REGTYPE)])
    with tarfile.open(path) as archive:
        config = 'sha256:'+hashlib.sha256(archive.extractfile('config.json').read()).hexdigest()
    document = {'source': {'metadata': {'imageID': config}},
                'files': [{'location': {'path': '/app.jar', 'layerID': digest},
                           'metadata': {'type': 'RegularFile', 'size': len(data)}}]}
    return candidate.JarFiles(path, document)


@pytest.mark.parametrize('contents, expected', [
    ([('X.class', b'\xca\xfe\xba\xbe')], '/app.jar:X.class'),
    ([('META-INF/resources/x.css', b'a{}')], '/app.jar:META-INF/resources/x.css'),
    ([('META-INF/maven/x/y/pom.xml', b'<project/>')], None),
    ([('X.class', b'wrong')], None),
])
def test_real_class_resource_and_metadata_only(tmp_path, contents, expected):
    files = reader(tmp_path, jar(contents))
    try:
        assert files.witness(artifact()) == expected
        assert files.stats['copied_bytes'] == 0
        assert files.layers_reader.stats['payload_read_bytes'] > 0
        assert not files.zips
    finally:
        files.close()


def test_directory_ledger_does_not_reuse_payload_or_zipfile(tmp_path):
    data = jar([('X.class', b'\xca\xfe\xba\xbe')])
    files = reader(tmp_path, data)
    try:
        for _ in range(3):
            assert files.witness(artifact()) == '/app.jar:X.class'
        assert len(files.indexes) == 1
        assert files.stats['zip_parse_entries'] == 1
        assert files.stats['zip_entries'] == 1
        assert files.stats['read_cache_hits'] > 0
        assert not files.read_cache and not files.cache_bytes
        assert files.stats['content_witness_hits'] == 2
    finally:
        files.close()


def test_nested_jar_uses_real_decompressed_class(tmp_path):
    files = reader(tmp_path, jar([('lib.jar', jar([('X.class', b'\xca\xfe\xba\xbe')]))]))
    try:
        assert files.witness(artifact(':lib.jar')) == '/app.jar:lib.jar:X.class'
        assert files.stats['nested_files'] == 1
    finally:
        files.close()


def test_traversal_duplicate_and_index_budgets_stay_rejected(tmp_path):
    files = reader(tmp_path, jar([('../X.class', b'\xca\xfe\xba\xbe')]))
    try:
        with pytest.raises(ValueError, match='Unsafe ZIP'):
            files.witness(artifact())
        assert not files.zips
    finally:
        files.close()


def test_fast_eocd_and_commented_fallback():
    for comment in (b'', b'comment'):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('x', b'y')
            archive.comment = comment
        assert candidate.directory(stream)[:2][0] == 1
    raw = jar([('x', b'y')])
    with pytest.raises(ValueError, match='offset layout'):
        candidate.directory(io.BytesIO(b'prefix'+raw))
    with patch.object(candidate.frozen, 'MAX_INDEX', 1), pytest.raises(ValueError, match='directory budget'):
        candidate.directory(io.BytesIO(raw))


def test_closed_cached_view_never_returns_cached_bytes(tmp_path):
    files = reader(tmp_path, jar([('X.class', b'\xca\xfe\xba\xbe')]))
    try:
        view = files.source('/app.jar')
        assert view.read(4)
        view.seek(0)
        view.close()
        with pytest.raises(ValueError, match='Closed cached'):
            view.read(4)
    finally:
        files.close()


@pytest.mark.parametrize('corrupt', [False, True])
def test_content_cache_requires_actual_equal_bytes_at_each_path(tmp_path, corrupt):
    first = jar([('X.class', b'\xca\xfe\xba\xbe')])
    second = first.replace(b'\xca\xfe\xba\xbe', b'bad!') if corrupt else first
    path, digest = fixture(tmp_path, [('a.jar', first, tarfile.REGTYPE), ('b.jar', second, tarfile.REGTYPE)])
    with tarfile.open(path) as archive:
        config = 'sha256:'+hashlib.sha256(archive.extractfile('config.json').read()).hexdigest()
    doc = {'source': {'metadata': {'imageID': config}}, 'files': [
        {'location': {'path': '/'+name, 'layerID': digest},
         'metadata': {'type': 'RegularFile', 'size': len(data)}} for name, data in [('a.jar', first), ('b.jar', second)]]}
    files = candidate.JarFiles(path, doc)
    try:
        assert files.witness({'locations': [{'path': '/a.jar'}]}) == '/a.jar:X.class'
        if corrupt:
            with pytest.raises(zipfile.BadZipFile):
                files.witness({'locations': [{'path': '/b.jar'}]})
            assert files.stats['content_witness_hits'] == 0
        else:
            assert files.witness({'locations': [{'path': '/b.jar'}]}) == '/b.jar:X.class'
            assert files.stats['content_witness_hits'] == 1
        assert files.stats['verification_read_bytes'] == len(first)+len(second)
    finally:
        files.close()


def test_verification_budget_cannot_return_unverified_witness(tmp_path):
    files = reader(tmp_path, jar([('X.class', b'\xca\xfe\xba\xbe')]))
    try:
        files.stats['verification_read_bytes'] = 8*1024**3
        with pytest.raises(candidate.frozen.BudgetExceeded, match='verification read budget'):
            files.witness(artifact())
        assert not files.confirmed_content and not files.file_hashes
    finally:
        files.close()


def test_witness_deadline_is_fail_closed(tmp_path):
    files = reader(tmp_path, jar([('X.class', b'\xca\xfe\xba\xbe')]))
    try:
        with patch.object(candidate.time, 'monotonic', return_value=files.started+181), pytest.raises(
                candidate.frozen.BudgetExceeded, match='deadline'):
            files.witness(artifact())
        assert not files.confirmed_content
    finally:
        files.close()

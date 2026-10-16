"""Independent post-only label tests; no classifier or prediction fixtures."""
import hashlib
import io
import stat
import struct
import zipfile

import label_reactor_nested_scope_r109 as labels
import pytest


def jar(entries, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


def inspect(raw, inventory=None):
    inventory = inventory or labels.ArchiveInventory()
    digest = hashlib.sha256(raw).hexdigest()
    return inventory, inventory.inspect(io.BytesIO(raw), digest, len(raw))


def component(gav='pkg:maven/example/library@1.0', digest='a' * 64):
    return {'type': 'library', 'name': 'library', 'purl': gav,
            'hashes': [{'alg': 'SHA-256', 'content': digest}]}


def test_nested_complete_hash_crc_and_no_name_identity():
    child = jar([('not/a/package/name.class', b'actual bytes')])
    raw = jar([('BOOT-INF/lib/filename-guess.jar', child), ('org/foo.class', b'opaque')])
    inventory, root = inspect(raw)
    digest = hashlib.sha256(child).hexdigest()
    index = labels.identity_index([component(digest=digest)])
    known, unknown = labels.nested_labels(inventory, '/image/app.jar', root['sha256'], {}, index)
    assert not unknown and len(known) == 1
    assert known[0]['coordinate'] == 'pkg:maven/example/library@1.0'
    assert known[0]['virtual_path'] == '/image/app.jar:BOOT-INF/lib/filename-guess.jar'
    assert known[0]['sha256'] == digest and known[0]['entry_crc_verified']
    assert known[0]['identity_status'] == 'UNIQUE_GLOBAL_REACTOR_CDX_SHA256'
    assert root['opaque_non_nested_classes'] == 1


def test_nested_unmatched_and_same_gav_qualified_conflict_remain_unknown():
    child = jar([('x.class', b'x')])
    inventory, root = inspect(jar([('looks-like-library-1.0.jar', child)]))
    digest = hashlib.sha256(child).hexdigest()
    known, unknown = labels.nested_labels(inventory, '/app.jar', root['sha256'], {}, {})
    assert not known and unknown[0]['reason'] == 'NO_UNIQUE_CONTROLLED_CDX_SHA256_IDENTITY'
    own = labels.identity_index([component(digest=digest)])
    global_index = labels.identity_index([component(digest=digest),
        component('pkg:maven/example/library@1.0?classifier=tests', digest)])
    known, unknown = labels.nested_labels(inventory, '/app.jar', root['sha256'], own, global_index)
    assert not known and unknown[0]['reason'] == 'CONFLICTING_GLOBAL_CONTROLLED_HASH_IDENTITIES'


def test_same_hash_two_gav_does_not_use_local_uniqueness():
    own = labels.identity_index([component()])
    global_index = labels.identity_index([component(), component('pkg:maven/other/lib@2')])
    identity, reason = labels.unique_identity('a' * 64, own, global_index)
    assert identity is None and reason == 'CONFLICTING_GLOBAL_CONTROLLED_HASH_IDENTITIES'


def test_all_member_hashes_and_crc_checked_including_metadata():
    raw = jar([('META-INF/LICENSE.txt', b'license'), ('x.class', b'class')])
    _, result = inspect(raw)
    assert result['all_regular_entry_crc_verified']
    assert result['entries'][0]['sha256'] == hashlib.sha256(b'license').hexdigest()
    broken = bytearray(raw)
    offset = broken.index(b'license')
    broken[offset] ^= 1
    with pytest.raises(zipfile.BadZipFile):
        inspect(bytes(broken))


@pytest.mark.parametrize('name', ['../x.class', '/absolute.class', r'win\path.class',
                                  'x/../relative.class', 'x:stream', './dot.class'])
def test_unsafe_paths_rejected_before_entry_read(name):
    inventory = labels.ArchiveInventory()
    raw = jar([(name.replace('\\', '/'), b'x')])
    if '\\' in name:
        raw = raw.replace(name.replace('\\', '/').encode(), name.encode())
    with pytest.raises(ValueError, match='UNSAFE_ZIP_MEMBER'):
        inspect(raw, inventory)
    assert inventory.stats['member_read_bytes'] == 0


def test_duplicate_and_symlink_rejected():
    with pytest.warns(UserWarning):
        duplicate = jar([('x', b'a'), ('x', b'b')])
    with pytest.raises(ValueError, match='DUPLICATE_ZIP_MEMBER'):
        inspect(duplicate)
    member = zipfile.ZipInfo('link')
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ValueError, match='UNSAFE_ZIP_MEMBER'):
        inspect(jar([(member, b'target')]))


def test_unusual_unix_directory_metadata_zero_bytes_is_safe_without_extraction():
    member = zipfile.ZipInfo('META-INF/maven/')
    member.create_system = 3
    member.external_attr = 0o177777 << 16
    _, result = inspect(jar([(member, b''), ('actual.class', b'bytes')]))
    assert result['entry_count'] == 2 and result['entries'][0]['directory']
    assert result['entries'][0]['bytes'] == 0
    assert result['all_regular_entry_crc_verified']


@pytest.mark.parametrize('kind,contents', [(0o177777, b'not-empty'),
                                          (stat.S_IFLNK | 0o777, b'')])
def test_unusual_directory_never_accepts_payload_or_symlink(kind, contents):
    member = zipfile.ZipInfo('META-INF/maven/')
    member.create_system = 3
    member.external_attr = kind << 16
    with pytest.raises(ValueError, match='UNSAFE_ZIP_MEMBER'):
        inspect(jar([(member, contents)]))


def test_encryption_and_central_truncation_rejected():
    raw = bytearray(jar([('x', b'bytes')]))
    offset = raw.index(b'PK\x01\x02')
    struct.pack_into('<H', raw, offset + 8, 1)
    with pytest.raises(ValueError, match='UNSAFE_ZIP_MEMBER'):
        inspect(bytes(raw))
    with pytest.raises(ValueError):
        inspect(bytes(raw[:-12]))


def test_nested_invalid_archive_cannot_be_labelled_by_whole_hash():
    inventory, root = inspect(jar([('nested.jar', b'not a zip')]))
    known, unknown = labels.nested_labels(inventory, '/app.jar', root['sha256'], {}, {})
    assert not known and len(unknown) == 2
    assert unknown[-1]['status'] == 'UNKNOWN_NESTED_CONTENT'
    assert unknown[-1]['reason'] == 'Missing ZIP directory'


def test_post_read_and_directory_budget_fail_closed(monkeypatch):
    monkeypatch.setattr(labels, 'MAX_READ', 2)
    with pytest.raises(ValueError, match='POST_MEMBER_READ_BUDGET'):
        inspect(jar([('x', b'123')]))
    monkeypatch.setattr(labels, 'MAX_DIRECTORY', 1)
    inventory = labels.ArchiveInventory()
    with pytest.raises(ValueError, match='POST_DIRECTORY_AGGREGATE_BUDGET'):
        inspect(jar([('x', b'1')]), inventory)
    assert inventory.stats['member_read_bytes'] == 0


def test_inflate_and_depth_budget_rejected(monkeypatch):
    with pytest.raises(ValueError, match='POST_MEMBER_SIZE_INFLATE_BUDGET'):
        inspect(jar([('huge', b'a' * 100_000)], zipfile.ZIP_DEFLATED))
    monkeypatch.setattr(labels, 'MAX_DEPTH', 0)
    _, result = inspect(jar([('nested.jar', jar([('x', b'x')]))]))
    assert result['nested_archives'][0]['inspection_status'] == 'UNKNOWN_NESTED_CONTENT'
    assert result['nested_archives'][0]['inspection_reason'] == 'POST_ARCHIVE_SIZE_DEPTH_BUDGET'


def test_untrusted_error_text_not_exported_as_internal_reason():
    assert labels.rejection_reason(ValueError('malicious archive text')) == 'UNSUPPORTED_ZIP_STRUCTURE'


def test_content_reuse_only_after_full_child_crc_and_hash_read():
    child = jar([('x', b'actual')])
    inventory, root = inspect(jar([('one.jar', child), ('two.jar', child)]))
    assert inventory.stats['content_reuses'] == 1
    assert inventory.stats['member_read_bytes'] == 2 * len(child) + len(b'actual')
    assert len(root['nested_archives']) == 2
    assert root['nested_archives'][0]['sha256'] == root['nested_archives'][1]['sha256']


def test_consume_rejects_size_mismatch_and_truncation():
    inventory = labels.ArchiveInventory()
    with pytest.raises(ValueError, match='ZIP_MEMBER_SIZE_MISMATCH'):
        inventory.consume(io.BytesIO(b'ab'), 1)
    with pytest.raises(ValueError, match='TRUNCATED_ZIP_MEMBER'):
        inventory.consume(io.BytesIO(b'a'), 2)

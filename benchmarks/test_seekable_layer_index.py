import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from unittest.mock import patch

import pytest
import seekable_layer_index as candidate


def tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, raw, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return stream.getvalue()


def fixture(tmp_path, entries, *, wrong_digest=False):
    layer = tar(entries)
    digest = 'sha256:' + (('0'*64) if wrong_digest else hashlib.sha256(layer).hexdigest())
    config = json.dumps({'rootfs': {'diff_ids': [digest]}}).encode()
    manifest = json.dumps([{'Config': 'config.json', 'Layers': ['layer.gz']}]).encode()
    path = tmp_path/'image.tar'
    path.write_bytes(tar([('manifest.json', manifest, tarfile.REGTYPE),
                          ('config.json', config, tarfile.REGTYPE),
                          ('layer.gz', gzip.compress(layer), tarfile.REGTYPE)]))
    return path, digest


def test_seekable_zip_view_without_whole_jar_copy(tmp_path):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as archive:
        archive.writestr('X.class', b'\xca\xfe\xba\xbe')
    data = raw.getvalue()
    path, digest = fixture(tmp_path, [('app.jar', data, tarfile.REGTYPE)])
    reader = candidate.Layers(path)
    try:
        for _ in range(2):
            view = reader.view('/app.jar', digest, len(data))
            with zipfile.ZipFile(view) as archive:
                assert archive.read('X.class') == b'\xca\xfe\xba\xbe'
        assert reader.stats['normalizations'] == 1
    finally:
        reader.close()


@pytest.mark.parametrize('entries', [
    [('a', b'x', tarfile.REGTYPE), ('./a', b'y', tarfile.REGTYPE)],
    [('../a', b'x', tarfile.REGTYPE)], [('C:\\a', b'x', tarfile.REGTYPE)],
])
def test_ambiguous_and_unsafe_names_rejected(tmp_path, entries):
    path, digest = fixture(tmp_path, entries)
    reader = candidate.Layers(path)
    try:
        with pytest.raises(ValueError, match='path'):
            reader.layer(digest)
        assert not reader.ready
        with pytest.raises(ValueError, match='Previously rejected'):
            reader.layer(digest)
    finally:
        reader.close()


def test_layer_digest_and_final_size_are_bound(tmp_path):
    path, digest = fixture(tmp_path, [('a', b'x', tarfile.REGTYPE)], wrong_digest=True)
    reader = candidate.Layers(path)
    try:
        with pytest.raises(ValueError, match='DiffID'):
            reader.view('/a', digest, 1)
    finally:
        reader.close()
    path, digest = fixture(tmp_path, [('a', b'x', tarfile.REGTYPE)])
    reader = candidate.Layers(path)
    try:
        with pytest.raises(ValueError, match='metadata mismatch'):
            reader.view('/a', digest, 2)
    finally:
        reader.close()


def test_links_are_never_followed(tmp_path):
    path, digest = fixture(tmp_path, [('a', b'', tarfile.SYMTYPE)])
    reader = candidate.Layers(path)
    try:
        with pytest.raises(ValueError, match='metadata mismatch'):
            reader.view('/a', digest, 0)
    finally:
        reader.close()


def test_disk_ratio_metadata_and_read_budgets(tmp_path):
    path, digest = fixture(tmp_path, [('a', b'x'*2000, tarfile.REGTYPE)])
    reader = candidate.Layers(path)
    try:
        with patch.object(candidate, 'MAX_DISK', 1), pytest.raises(ValueError, match='normalization budget'):
            reader.layer(digest)
        assert not reader.ready
    finally:
        reader.close()
    reader = candidate.Layers(path)
    try:
        with patch.object(candidate, 'MAX_RATIO', 1), pytest.raises(ValueError, match='normalization budget'):
            reader.layer(digest)
        assert not reader.ready
    finally:
        reader.close()
    reader = candidate.Layers(path)
    try:
        with patch.object(candidate, 'MAX_METADATA', 1), pytest.raises(ValueError, match='metadata budget'):
            reader.layer(digest)
    finally:
        reader.close()
    reader = candidate.Layers(path)
    try:
        view = reader.view('/a', digest, 2000)
        with patch.object(candidate, 'MAX_READ', 1), pytest.raises(ValueError, match='read budget'):
            view.read(2)
        with pytest.raises(ValueError, match='outside'):
            view.seek(2001)
        with patch.object(candidate, 'MAX_READ_TOTAL', 2):
            assert view.read(2) == b'xx'
            with pytest.raises(ValueError, match='read budget'):
                view.read(1)
        view.close()
        with pytest.raises(ValueError, match='Closed'):
            view.read(1)
    finally:
        reader.close()


def test_oversized_extension_rejected_before_tarfile_allocation():
    member = tarfile.TarInfo('pax')
    member.type, member.size = tarfile.XHDTYPE, candidate.MAX_EXTENSION+1
    raw = member.tobuf() + bytes(member.size+2048)
    with patch.object(candidate.tarfile, 'open', side_effect=AssertionError('too early')), pytest.raises(
            ValueError, match='extension budget'):
        candidate.index(io.BytesIO(raw), len(raw))


def test_pax_size_override_and_nonzero_tail_rejected():
    payload = b'10 size=1\n'
    member = tarfile.TarInfo('pax')
    member.type, member.size = tarfile.XHDTYPE, len(payload)
    raw = member.tobuf()+payload+bytes(512-len(payload))+bytes(1024)
    with pytest.raises(ValueError, match='PAX layout'):
        candidate.preflight(io.BytesIO(raw), len(raw))
    raw = tar([('a', b'x', tarfile.REGTYPE)])+b'bad'
    with pytest.raises(ValueError, match='trailing'):
        candidate.preflight(io.BytesIO(raw), len(raw))


def test_global_pax_and_deep_extension_chains_are_rejected():
    member = tarfile.TarInfo('global')
    member.type, member.size = tarfile.XGLTYPE, 0
    raw = member.tobuf()+bytes(1024)
    with pytest.raises(ValueError, match='Unsupported TAR'):
        candidate.preflight(io.BytesIO(raw), len(raw))
    member.type = tarfile.GNUTYPE_LONGNAME
    raw = member.tobuf()*9+bytes(1024)
    with pytest.raises(ValueError, match='chain budget'):
        candidate.preflight(io.BytesIO(raw), len(raw))


def test_remaining_metadata_checked_before_tarfile_allocation():
    raw = tar([('a', b'x', tarfile.REGTYPE)])
    with patch.object(candidate.tarfile, 'open', side_effect=AssertionError('too early')), pytest.raises(
            ValueError, match='Aggregate metadata budget'):
        candidate.index(io.BytesIO(raw), len(raw), remaining=1)

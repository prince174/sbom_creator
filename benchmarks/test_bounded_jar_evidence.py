import io
import json
import stat
import struct
import tarfile
import zipfile
from contextlib import nullcontext

import pytest
from bounded_jar_evidence import (
    CHUNK,
    MAX_COPY,
    MAX_INDEX,
    MAX_OUTER,
    BudgetExceeded,
    JarFiles,
    zip_index,
)

from sbom_creator import payload


def jar(contents, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=compression) as archive:
        for name, data in contents:
            archive.writestr(name, data)
    return stream.getvalue()


def image(tmp_path, raw=None, file_path=None):
    if file_path is None:
        file_path = tmp_path / 'app.jar'
        file_path.write_bytes(raw)
    layer = tmp_path / 'layer.tar'
    with tarfile.open(layer, 'w') as archive:
        archive.add(file_path, arcname='app.jar')
    output = tmp_path / 'image.tar'
    with tarfile.open(output, 'w') as archive:
        for name, data in [('manifest.json', [{'Config': 'config.json', 'Layers': ['layer.tar']}]),
                           ('config.json', {'rootfs': {'diff_ids': ['sha256:layer']}})]:
            raw = json.dumps(data).encode()
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        archive.add(layer, arcname='layer.tar')
    document = {'files': [{'location': {'path': '/app.jar', 'layerID': 'sha256:layer'},
                            'metadata': {'type': 'RegularFile', 'size': file_path.stat().st_size}}]}
    return output, document


def artifact(nested=''):
    return {'locations': [{'path': '/app.jar'}], 'metadata': {'virtualPath': '/app.jar' + nested}}


@pytest.mark.parametrize('contents,confirmed,kind', [
    ([('x.class', b'\xca\xfe\xba\xbe')], True, 'class_witnesses'),
    ([('x.class', b'not-class')], False, 'class_witnesses'),
    ([('META-INF/maven/a/b/pom.xml', b'<project/>')], False, 'class_witnesses'),
    ([('META-INF/MANIFEST.MF', b'Manifest-Version: 1')], False, 'class_witnesses'),
    ([('pom.xml', b'<project/>')], False, 'resource_witnesses'),
    ([('package.json', b'{"name":"metadata"}')], False, 'resource_witnesses'),
    ([('META-INF/resources/web.css', b'a{}')], True, 'resource_witnesses'),
    ([('config.properties', b'key=value')], True, 'resource_witnesses'),
    ([('empty.json', b'')], False, 'resource_witnesses'),
])
def test_class_resource_and_metadata_only(tmp_path, contents, confirmed, kind):
    archive, document = image(tmp_path, jar(contents))
    files = JarFiles(archive, document)
    try:
        assert bool(files.witness(artifact())) == confirmed
        assert files.stats[kind] == int(confirmed)
    finally:
        files.close()


def test_large_outer_spooled_once_old_memory_limit_unchanged(tmp_path):
    source = tmp_path / 'large.jar'
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('x.class', b'\xca\xfe\xba\xbe')
        with archive.open('padding.bin', 'w') as stream:
            for _ in range(33):
                stream.write(b'x' * CHUNK)
    archive, document = image(tmp_path, file_path=source)
    files = JarFiles(archive, document)
    try:
        assert source.stat().st_size > payload.MAX_READ
        assert payload._java(artifact(), files) is None
        assert files.witness(artifact()) == '/app.jar:x.class'
        copied = files.stats['copied_bytes']
        assert files.witness(artifact()) == '/app.jar:x.class'
        assert files.stats['copied_bytes'] == copied == source.stat().st_size
        assert files.stats['source_files'] == 1
    finally:
        files.close()


def test_nested_jar_and_owner_path_mismatch(tmp_path):
    raw = jar([('lib.jar', jar([('impl.class', b'\xca\xfe\xba\xbe')]))])
    archive, document = image(tmp_path, raw)
    files = JarFiles(archive, document)
    try:
        assert files.witness(artifact(':lib.jar')) == '/app.jar:lib.jar:impl.class'
        assert files.witness({'locations': [{'path': '/app.jar'}],
                              'metadata': {'virtualPath': '/app.jar-other:lib.jar'}}) is None
    finally:
        files.close()


@pytest.mark.parametrize('names', [['../bad.class'], ['/bad.class'], ['a\\bad.class'],
                                  ['x.class', 'x.class']])
def test_reject_unsafe_or_duplicate_names(tmp_path, names):
    with pytest.warns(UserWarning) if len(names) == 2 else nullcontext():
        raw = jar([(name, b'\xca\xfe\xba\xbe') for name in names])
    if '\\' in names[0]:
        # ZipInfo on Windows normalizes separators when writing; forge raw bytes.
        raw = raw.replace(names[0].replace('\\', '/').encode(), names[0].encode())
    archive, document = image(tmp_path, raw)
    files = JarFiles(archive, document)
    try:
        with pytest.raises(ValueError, match='Unsafe|Ambiguous'):
            files.witness(artifact())
    finally:
        files.close()


def test_zip_bomb_nested_rejected_before_inflation(tmp_path):
    nested = b'0' * CHUNK
    raw = jar([('lib.jar', nested)], zipfile.ZIP_DEFLATED)
    archive, document = image(tmp_path, raw)
    files = JarFiles(archive, document)
    try:
        with pytest.raises(BudgetExceeded, match='inflate'):
            files.witness(artifact(':lib.jar'))
        assert files.stats['nested_files'] == 0
    finally:
        files.close()


def test_copy_budget_rejected_before_any_read(tmp_path):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)
    try:
        files.stats['copied_bytes'] = MAX_COPY
        with pytest.raises(BudgetExceeded, match='budget'):
            files.witness(artifact())
        assert files.stats['source_files'] == 0
    finally:
        files.close()


def test_huge_directory_declared_before_zipfile_allocation():
    raw = struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 1, 1, MAX_INDEX + 1, 0, 0)
    # Plausible offset range but oversized directory should still fail early.
    stream = io.BytesIO(b'x' * (MAX_INDEX + 1) + raw)
    with pytest.raises(BudgetExceeded, match='directory'):
        zip_index(stream)


def test_copy_reads_in_chunks_not_whole_outer(tmp_path):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)

    class Chunked(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= CHUNK
            return super().read(size)
    try:
        output = files.copy(Chunked(b'x' * (CHUNK + 1)), CHUNK + 1, 2 * CHUNK)
        assert output.seek(0, 2) == CHUNK + 1
    finally:
        files.close()


def test_symlink_class_is_not_payload(tmp_path):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as archive:
        member = zipfile.ZipInfo('fake.class')
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, b'\xca\xfe\xba\xbe')
    archive, document = image(tmp_path, raw.getvalue())
    files = JarFiles(archive, document)
    try:
        with pytest.raises(ValueError, match='Unsafe'):
            files.witness(artifact())
    finally:
        files.close()


@pytest.mark.parametrize('mutate,error', [
    (lambda d: d['files'][0]['location'].update(layerID='sha256:missing'), 'Missing final layer'),
    (lambda d: d['files'][0]['metadata'].update(size=1), 'metadata disagree'),
    (lambda d: d['files'][0]['metadata'].update(size=MAX_OUTER + 1), 'disk budget'),
])
def test_final_layer_binding_and_size_limits(tmp_path, mutate, error):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    mutate(document)
    files = JarFiles(archive, document)
    try:
        with pytest.raises(ValueError, match=error):
            files.witness(artifact())
        assert files.stats['copied_bytes'] == 0
    finally:
        files.close()


def test_depth_limit_rejects_before_source_copy(tmp_path):
    archive, document = image(tmp_path, jar([('x.class', b'\xca\xfe\xba\xbe')]))
    files = JarFiles(archive, document)
    try:
        with pytest.raises(BudgetExceeded, match='depth'):
            files.witness(artifact(':nested.jar' * 9))
        assert files.stats['source_files'] == 0
    finally:
        files.close()


def test_zip64_not_silently_successful():
    raw = struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 65535, 65535, 0, 0, 0)
    with pytest.raises(ValueError, match='ZIP64'):
        zip_index(io.BytesIO(raw))

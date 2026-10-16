"""Adversarial checks for content-bound nested payload reuse.

Fixtures contain only scanner inputs and actual image bytes.  No reference SBOM
or expected package names are passed to the reader or identity bridge.
"""
import copy
import gzip
import hashlib
import io
import json
import random
import struct
import tarfile
import zipfile
from types import SimpleNamespace

import pytest

from sbom_creator import core
from sbom_creator.acquire import Settings
from sbom_creator.image_java.runtime import corroborate
from sbom_creator.image_java.seekable_layer_index import Window
from sbom_creator.image_java.stored_jar_evidence import CachedWindow
from sbom_creator.image_java.stored_jar_evidence import JarFiles as StoredJarFiles


def jar(entries, compression=zipfile.ZIP_STORED, *, comment=b''):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=compression) as archive:
        for name, raw in entries:
            archive.writestr(name, raw)
        archive.comment = comment
    return output.getvalue()


def tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, raw in entries:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def fixture(tmp_path, nested=None, *, outers=None, compression=zipfile.ZIP_STORED):
    if nested is None:
        nested = jar([('X.class', b'\xca\xfe\xba\xbe' + bytes(range(256))*256)])
    if outers is None:
        # Different full-archive hashes prevent the old outer-only cache from
        # accidentally satisfying a test of cross-outer nested reuse.
        outers = [jar([('lib/core.jar', nested), ('application.txt', bytes([number]))], compression)
                  for number in (1, 2)]
    layer = tar([(f'app{number}.jar', raw) for number, raw in enumerate(outers)])
    layer_id = 'sha256:'+hashlib.sha256(layer).hexdigest()
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'diff_ids': [layer_id]}}).encode()
    config_id = 'sha256:'+hashlib.sha256(config).hexdigest()
    image_path = tmp_path/'nested-reuse-image.tar'
    image_path.write_bytes(tar([
        ('manifest.json', json.dumps([{'Config': 'config.json', 'Layers': ['layer.gz']}]).encode()),
        ('config.json', config), ('layer.gz', gzip.compress(layer))]))
    image = {'source': {'metadata': {'imageID': config_id}}, 'artifacts': [], 'files': []}
    peer = {'metadata': {'component': {'properties': [
        {'name': 'aquasecurity:trivy:ImageID', 'value': config_id}]}}, 'components': []}
    for number, outer in enumerate(outers):
        path = f'/app{number}.jar'
        image['files'].append({'location': {'path': path, 'layerID': layer_id},
                               'metadata': {'size': len(outer), 'type': 'RegularFile'}})
        image['artifacts'].append({'id': f'core-{number}', 'name': 'core', 'version': '1',
            'type': 'java-archive', 'foundBy': 'java-archive-cataloger',
            'purl': 'pkg:maven/source/core@1', 'metadata': {'virtualPath': path+':lib/core.jar'},
            'locations': [{'path': path, 'layerID': layer_id, 'accessPath': path+':lib/core.jar'}]})
        peer['components'].append({'name': 'core', 'group': 'example', 'version': str(number+1),
            'purl': f'pkg:maven/example/core@{number+1}', 'bom-ref': f'peer-{number}', 'properties': [
                {'name': 'aquasecurity:trivy:FilePath', 'value': path.lstrip('/')+'/lib/core.jar'},
                {'name': 'aquasecurity:trivy:LayerDiffID', 'value': layer_id}]})
    return image, peer, image_path


def mutation(raw, field, value):
    """Change the nested member's local header while retaining its directory."""
    offsets = {'flags': (6, '<H'), 'method': (8, '<H'), 'crc': (14, '<L'),
               'compressed_size': (18, '<L'), 'size': (22, '<L')}
    offset, fmt = offsets[field]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        start = archive.getinfo('lib/core.jar').header_offset
    changed = bytearray(raw)
    struct.pack_into(fmt, changed, start+offset, value)
    return bytes(changed)


def no_witness(files, artifact):
    try:
        assert files.witness(artifact) is None
    except (ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
        pass


def test_stored_nested_archives_use_bounded_windows_instead_of_full_copies(tmp_path):
    nested = jar([('X.class', b'\xca\xfe\xba\xbe'+random.Random(106).randbytes(2*1024*1024))])
    image, _, archive = fixture(tmp_path, nested=nested)
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        for number, artifact in enumerate(image['artifacts']):
            assert files.witness(artifact) == f'/app{number}.jar:lib/core.jar:X.class'
        assert files.stats['copied_bytes'] == 0
        assert files.stats['nested_window_files'] == 2
        assert files.layers_reader.stats['payload_read_bytes'] < 128*1024
    finally:
        files.close()


def test_stored_reader_requires_explicit_opt_in_and_legacy_remains_default(tmp_path):
    assert Settings().java_nested_windows is False
    image, peer, archive = fixture(tmp_path)
    legacy, physical, envelope, audit = corroborate(image, archive, peer, temporary=tmp_path)
    assert 'reader_policy' not in envelope
    assert 'nested_window_files' not in audit['jar_resources']
    assert audit['jar_resources']['copied_bytes'] > 0
    result = core.reconcile({'artifacts': []}, legacy, payload_evidence=physical, identity_envelope=envelope)
    assert result['coverage']['policy_version'] == 'image-identity-payload-v4'
    adapted, physical, envelope, audit = corroborate(image, archive, peer, temporary=tmp_path, nested_windows=True)
    assert envelope['reader_policy'] == 'stored-nested-directory-lru-v1'
    assert audit['jar_resources']['nested_window_files'] == 2
    assert audit['jar_resources']['copied_bytes'] == 0
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert result['coverage']['policy_version'] == 'image-identity-payload-v6'


@pytest.mark.parametrize('raw,expected', [('true', True), ('false', False), ('TRUE', True)])
def test_nested_window_environment_selector_is_explicit_boolean(monkeypatch, raw, expected):
    monkeypatch.setenv('SBOM_JAVA_NESTED_WINDOWS', raw)
    assert Settings.from_env().java_nested_windows is expected


@pytest.mark.parametrize('raw', ['1', 'enabled', 'auto', ''])
def test_nested_window_environment_selector_rejects_ambiguous_values(monkeypatch, raw):
    monkeypatch.setenv('SBOM_JAVA_NESTED_WINDOWS', raw)
    with pytest.raises(ValueError, match='SBOM_JAVA_NESTED_WINDOWS must be true or false'):
        Settings.from_env()


def test_valid_stored_data_descriptor_uses_existing_bounded_copy_fallback(tmp_path):
    class Unseekable(io.BytesIO):
        def seek(self, *args):
            raise OSError('Sequential fixture')
    nested = jar([('X.class', b'\xca\xfe\xba\xbe')])
    output = Unseekable()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('lib/core.jar', nested)
    outer = output.getvalue()
    assert struct.unpack_from('<H', outer, 6)[0] & 8
    image, _, archive = fixture(tmp_path, outers=[outer])
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0]) == '/app0.jar:lib/core.jar:X.class'
        assert files.stats['copied_bytes'] == len(nested)
        assert files.stats['nested_window_files'] == 0
    finally:
        files.close()


def test_valid_deflated_nested_archive_retains_bounded_copy_path(tmp_path):
    nested = jar([('X.class', b'\xca\xfe\xba\xbe'+random.Random(8).randbytes(2048))])
    image, _, archive = fixture(tmp_path, nested=nested, compression=zipfile.ZIP_DEFLATED)
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        for artifact in image['artifacts']:
            assert files.witness(artifact)
        assert files.stats['copied_bytes'] == len(nested)*2
        assert files.stats['nested_window_files'] == 0
    finally:
        files.close()


def test_distinct_outer_archives_do_not_share_identity_with_nested_payload(tmp_path):
    image, peer, archive = fixture(tmp_path)
    adapted, physical, envelope, _ = corroborate(image, archive, peer, temporary=tmp_path, nested_windows=True)
    assert all(physical[a['id']]['status'] == 'confirmed' for a in image['artifacts'])
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    # Payload bytes are identical; each actual peer path keeps its own version.
    assert {a['purl'] for a in result['selected_syft']['artifacts']} == {
        'pkg:maven/example/core@1', 'pkg:maven/example/core@2'}


@pytest.mark.parametrize('binding', ['layer', 'path', 'image'])
def test_nested_payload_reuse_never_repairs_bad_identity_binding(tmp_path, binding):
    image, peer, archive = fixture(tmp_path)
    peer = copy.deepcopy(peer)
    if binding == 'image':
        peer['metadata']['component']['properties'][0]['value'] = 'sha256:'+'f'*64
        with pytest.raises(ValueError, match='config identity|config digest|mismatch'):
            corroborate(image, archive, peer, temporary=tmp_path, nested_windows=True)
        return
    name = 'LayerDiffID' if binding == 'layer' else 'FilePath'
    value = 'sha256:'+'f'*64 if binding == 'layer' else 'not-the-actual-file.jar/lib/core.jar'
    for prop in peer['components'][1]['properties']:
        if prop['name'] == 'aquasecurity:trivy:'+name:
            prop['value'] = value
    adapted, physical, envelope, _ = corroborate(image, archive, peer, temporary=tmp_path, nested_windows=True)
    assert physical['core-1']['status'] == 'confirmed'  # Physical fact is retained.
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert {a['purl'] for a in result['selected_syft']['artifacts']} == {'pkg:maven/example/core@1'}


def test_same_central_directory_changed_nested_body_cannot_reuse_positive_witness(tmp_path):
    good = jar([('X.class', b'\xca\xfe\xba\xbe')])
    bad = good.replace(b'\xca\xfe\xba\xbe', b'bad!', 1)
    assert good[good.index(b'PK\x01\x02'):] == bad[bad.index(b'PK\x01\x02'):]
    outers = [jar([('lib/core.jar', good)]), jar([('lib/core.jar', bad)])]
    image, _, archive = fixture(tmp_path, outers=outers)
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0]) == '/app0.jar:lib/core.jar:X.class'
        no_witness(files, image['artifacts'][1])
    finally:
        files.close()


def test_stored_nested_crc_checks_actual_body_not_just_matching_headers(tmp_path):
    nested = jar([('X.class', b'\xca\xfe\xba\xbe'+random.Random(117).randbytes(8192))])
    good = jar([('lib/core.jar', nested)])
    bad = bytearray(good)
    with zipfile.ZipFile(io.BytesIO(good)) as outer:
        member = outer.getinfo('lib/core.jar')
        nested_offset = member.header_offset+30+len(member.filename.encode())
    with zipfile.ZipFile(io.BytesIO(nested)) as inner:
        member = inner.getinfo('X.class')
        class_offset = nested_offset+member.header_offset+30+len(member.filename.encode())
    # Keep CAFEBABE, LFH, CD, sizes, and both declared CRCs unchanged.  The old
    # full nested copy rejected this when the containing ZipExtFile reached EOF.
    # A direct view must not silently lose that corruption check.
    bad[class_offset+6000] ^= 1
    image, _, archive = fixture(tmp_path, outers=[good, bytes(bad)])
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0])
        no_witness(files, image['artifacts'][1])
    finally:
        files.close()


@pytest.mark.parametrize('field,value', [('flags', 1), ('flags', 8), ('method', 8), ('crc', 0),
    ('compressed_size', 1), ('size', 1)])
def test_stored_nested_local_header_disagreement_cannot_bypass_reader(tmp_path, field, value):
    good = jar([('lib/core.jar', jar([('X.class', b'\xca\xfe\xba\xbe')]))])
    bad = mutation(good, field, value)
    image, _, archive = fixture(tmp_path, outers=[good, bad])
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0])
        no_witness(files, image['artifacts'][1])
    finally:
        files.close()


@pytest.mark.parametrize('corruption', ['signature', 'name', 'truncated'])
def test_corrupt_local_nested_member_cannot_take_cached_proof(tmp_path, corruption):
    nested = jar([('X.class', b'\xca\xfe\xba\xbe')])
    good = jar([('lib/core.jar', nested)])
    bad = bytearray(good)
    if corruption == 'signature':
        bad[:4] = b'bad!'
    elif corruption == 'name':
        bad[30:42] = b'lib/wrongjar'
    else:
        # Shrink the local nested payload; offsets in the central directory no
        # longer describe a complete physical member.
        del bad[42:46]
    image, _, archive = fixture(tmp_path, outers=[good, bytes(bad)])
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0])
        no_witness(files, image['artifacts'][1])
    finally:
        files.close()


def test_nested_range_overlapping_central_directory_is_rejected(tmp_path):
    nested = jar([('X.class', b'\xca\xfe\xba\xbe')])
    good = jar([('lib/core.jar', nested)])
    bad = bytearray(good)
    directory_offset = struct.unpack_from('<L', bad, bad.rfind(b'PK\x05\x06')+16)[0]
    # Matching LFH/CD declarations do not authorize reading directory bytes as
    # nested payload.  ZipFile.open's overlap check must remain in the path.
    for offset in (18, 22):
        struct.pack_into('<L', bad, offset, len(nested)+10)
    for offset in (20, 24):
        struct.pack_into('<L', bad, directory_offset+offset, len(nested)+10)
    image, _, archive = fixture(tmp_path, outers=[good, bytes(bad)])
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0])
        no_witness(files, image['artifacts'][1])
    finally:
        files.close()


def test_identical_metadata_only_nested_archives_never_gain_class_witness(tmp_path):
    image, _, archive = fixture(tmp_path, nested=jar([('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n'),
        ('META-INF/maven/example/pom.properties', b'version=1'), ('pom.xml', b'<project/>')]))
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert all(files.witness(a) is None for a in image['artifacts'])
        assert files.stats['class_witnesses'] == 0
        assert files.stats['resource_witnesses'] == 0
    finally:
        files.close()


def test_nested_compression_bomb_remains_unknown_with_repeated_outer_paths(tmp_path):
    # The outer deflate expansion ratio exceeds the unchanged 200x cap.
    nested = jar([('X.class', b'\xca\xfe\xba\xbe'+bytes(1024*1024))])
    image, _, archive = fixture(tmp_path, nested=nested, compression=zipfile.ZIP_DEFLATED)
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        for artifact in image['artifacts']:
            no_witness(files, artifact)
        assert files.stats['nested_files'] == 0
    finally:
        files.close()


@pytest.mark.parametrize('read_size,count,expected_entries', [(4, 4100, 4096), (64*1024, 257, 256)])
def test_persistent_range_cache_keeps_existing_entry_and_byte_caps(read_size, count, expected_entries):
    owner = SimpleNamespace(read_cache={}, cache_bytes=0, stats={
        'read_cache_hits': 0, 'range_cache_bytes': 0, 'range_cache_entries': 0})
    layer = SimpleNamespace(stats={'payload_read_bytes': 0})
    raw = bytes(range(256)) * ((read_size*count+255)//256)
    stream = io.BytesIO(raw)
    with CachedWindow(owner, Window(layer, stream, 0, len(raw))) as view:
        for _ in range(count):
            assert view.read(read_size)
        assert len(owner.read_cache) == expected_entries
        assert owner.cache_bytes <= 16*1024*1024
        assert owner.stats['range_cache_entries'] == expected_entries
        charged = layer.stats['payload_read_bytes']
        view.seek(0)
        assert view.read(read_size) == raw[:read_size]
        assert layer.stats['payload_read_bytes'] == charged
    # Reuse is conditioned on exact physical offset, not only length/stream.
    with CachedWindow(owner, Window(layer, stream, 1, len(raw)-1)) as shifted:
        assert shifted.read(read_size) == raw[1:read_size+1]
        assert layer.stats['payload_read_bytes'] == charged+read_size


def test_new_stored_member_cannot_bypass_exhausted_verification_budget_with_cached_outer(tmp_path):
    first = jar([('First.class', b'\xca\xfe\xba\xbe')])
    second = jar([('Second.class', b'\xca\xfe\xba\xbe'+random.Random(1062).randbytes(8192))])
    outer = jar([('lib/core.jar', first), ('lib/second.jar', second)])
    image, _, archive = fixture(tmp_path, outers=[outer])
    next_artifact = copy.deepcopy(image['artifacts'][0])
    next_artifact['id'] = 'second'
    next_artifact['metadata']['virtualPath'] = '/app0.jar:lib/second.jar'
    next_artifact['locations'][0]['accessPath'] = '/app0.jar:lib/second.jar'
    files = StoredJarFiles(archive, image, temporary=tmp_path)
    try:
        assert files.witness(image['artifacts'][0]) == '/app0.jar:lib/core.jar:First.class'
        assert ('/app0.jar', len(outer)) in files.file_hashes
        assert files.read_cache  # Persistent metadata cache is already populated.
        window = files.source('/app0.jar').window
        with zipfile.ZipFile(io.BytesIO(outer)) as parsed:
            member = parsed.getinfo('lib/second.jar')
            body_start = window.offset+member.header_offset+30+len(member.filename.encode())+len(member.extra)
            body_end = body_start+member.file_size

        class RefuseBodyReads:
            def __getattr__(self, name):
                return getattr(window_stream, name)

            def read(self, amount=-1):
                position = window_stream.tell()
                end = position+amount if amount >= 0 else body_end
                assert not (position < body_end and end > body_start), 'Unbudgeted stored-member body read'
                return window_stream.read(amount)

        window_stream = window.stream
        window.stream = RefuseBodyReads()
        files.stats['verification_read_bytes'] = 8*1024**3-1
        with pytest.raises(ValueError, match='Content verification read budget'):
            files.witness(next_artifact)
        assert files.stats['verification_read_bytes'] == 8*1024**3-1
        assert files.stats['class_witnesses'] == 1
        assert files.stats['stored_crc_verifications'] == 1
        assert ('/app0.jar', 'lib/second.jar') not in files.spools
    finally:
        files.close()

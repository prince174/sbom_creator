"""Crane config-name compatibility does not relax image-layer path checks."""
import hashlib
import io
import json
import tarfile

import pytest

from sbom_creator.image_java import seekable_layer_index as reader


def archive_bytes(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = 'real-config.json'
            else:
                info.size = len(data)
            archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
    return stream.getvalue()


def docker_tar(tmp_path, *, name=None, extra=(), kind=tarfile.REGTYPE, layer_members=None):
    layer = archive_bytes(layer_members) if layer_members else None
    diff_ids = ['sha256:' + hashlib.sha256(layer).hexdigest()] if layer else []
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'diff_ids': diff_ids}}).encode()
    digest = 'sha256:' + hashlib.sha256(config).hexdigest()
    config_name = name or digest
    manifest = json.dumps([{'Config': config_name, 'Layers': ['layer.tar'] if layer else []}]).encode()
    members = [(config_name, config, kind), ('manifest.json', manifest, tarfile.REGTYPE), *extra]
    if layer:
        members.append(('layer.tar', layer, tarfile.REGTYPE))
    target = tmp_path / 'image.tar'
    target.write_bytes(archive_bytes(members))
    return target, digest, diff_ids


def test_crane_root_config_sha256_is_accepted(tmp_path):
    path, digest, _ = docker_tar(tmp_path)
    layers = reader.Layers(path)
    try:
        assert layers.config_digest == digest and not layers.mapping
    finally:
        layers.close()


def test_legacy_docker_config_name_is_unchanged(tmp_path):
    path, digest, _ = docker_tar(tmp_path, name='config.json')
    layers = reader.Layers(path)
    try:
        assert layers.config_digest == digest
    finally:
        layers.close()


def test_digest_name_requires_actual_complete_config_hash(tmp_path):
    path, _, _ = docker_tar(tmp_path, name='sha256:' + '0' * 64)
    with pytest.raises(ValueError, match='Content-addressed Docker config mismatch'):
        reader.Layers(path)


def test_unused_digest_named_entry_is_rejected(tmp_path):
    path, _, _ = docker_tar(tmp_path, name='config.json', extra=[('sha256:' + 'a' * 64, b'x', tarfile.REGTYPE)])
    with pytest.raises(ValueError, match='Unreferenced digest-named Docker config'):
        reader.Layers(path)


@pytest.mark.parametrize('name', ['C:config', 'file:stream', 'sub/sha256:' + 'a' * 64,
    './sha256:' + 'a' * 64, 'sha256:' + 'A' * 64, 'sha256:' + 'a' * 63,
    '../sha256:' + 'a' * 64, '/sha256:' + 'a' * 64, 'sha256:' + 'a' * 64 + ':stream'])
def test_outer_exception_is_exact_root_lowercase_digest_only(tmp_path, name):
    path, _, _ = docker_tar(tmp_path, name=name)
    with pytest.raises(ValueError):
        reader.Layers(path)


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_digest_named_config_is_not_a_link_or_directory(tmp_path, kind):
    path, _, _ = docker_tar(tmp_path, kind=kind)
    with pytest.raises(ValueError):
        reader.Layers(path)


def test_inner_layer_digest_colon_is_still_rejected(tmp_path):
    path, _, diff_ids = docker_tar(tmp_path, layer_members=[('sha256:' + 'a' * 64, b'code', tarfile.REGTYPE)])
    layers = reader.Layers(path)
    try:
        with pytest.raises(ValueError, match='Unsafe TAR path'):
            layers.layer(diff_ids[0])
    finally:
        layers.close()


def test_default_canonical_and_index_still_reject_digest_colon():
    name = 'sha256:' + 'a' * 64
    with pytest.raises(ValueError):
        reader.canonical(name)
    raw = archive_bytes([(name, b'code', tarfile.REGTYPE)])
    with pytest.raises(ValueError):
        reader.index(io.BytesIO(raw), len(raw))


def test_duplicate_root_config_still_rejected(tmp_path):
    path, _, _ = docker_tar(tmp_path)
    with tarfile.open(path) as archive:
        members = [(entry.name, archive.extractfile(entry).read(), entry.type) for entry in archive]
    path.write_bytes(archive_bytes([*members, members[0]]))
    with pytest.raises(ValueError, match='Duplicate canonical TAR path'):
        reader.Layers(path)


@pytest.mark.parametrize('extension', ['pax', 'gnu'])
@pytest.mark.parametrize('effective_name', ['./sha256:' + 'a' * 64, 'dir/sha256:' + 'a' * 64])
def test_extension_effective_name_cannot_escape_exact_root_exception(extension, effective_name):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
        if extension == 'gnu':
            data = effective_name.encode() + b'\x00'
            info = tarfile.TarInfo('././@LongLink')
            info.type, info.size = tarfile.GNUTYPE_LONGNAME, len(data)
            archive.addfile(info, io.BytesIO(data))
        item = tarfile.TarInfo('placeholder')
        item.size = 1
        if extension == 'pax':
            item.pax_headers = {'path': effective_name}
        archive.addfile(item, io.BytesIO(b'x'))
    raw = stream.getvalue()
    with pytest.raises(ValueError, match='Unsafe TAR path'):
        reader.index(io.BytesIO(raw), len(raw), docker_config=True)


def test_content_addressed_config_still_binds_to_catalog_image_id(tmp_path):
    from sbom_creator.image_java.archive_component_evidence import JarFiles
    path, digest, _ = docker_tar(tmp_path)
    assert digest != 'sha256:' + 'f' * 64
    with pytest.raises(ValueError, match='Physical config differs'):
        JarFiles(path, {'source': {'metadata': {'imageID': 'sha256:' + 'f' * 64}}, 'files': []})


def test_oversized_config_rejected_before_extracting_body(tmp_path, monkeypatch):
    config = b'x' * (4 * reader.CHUNK + 1)
    name = 'sha256:' + hashlib.sha256(config).hexdigest()
    manifest = json.dumps([{'Config': name, 'Layers': []}]).encode()
    path = tmp_path / 'oversized.tar'
    path.write_bytes(archive_bytes([(name, config, tarfile.REGTYPE),
        ('manifest.json', manifest, tarfile.REGTYPE)]))
    original = tarfile.TarFile.extractfile

    def guarded(self, member):
        assert member.name != name, 'Oversized config body must not be read'
        return original(self, member)

    monkeypatch.setattr(tarfile.TarFile, 'extractfile', guarded)
    with pytest.raises(ValueError, match='Invalid image metadata'):
        reader.Layers(path)

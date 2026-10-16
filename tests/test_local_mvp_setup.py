"""Local deployment bootstrap safety; no Docker daemon or external registry."""
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import prepare_local_mvp as prepare
import publish_local_samples as samples


def descriptor(raw, media):
    return {'digest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'size': len(raw), 'mediaType': media}


def image_archive(path, *, bad_blob=False, duplicate=False, symlink=False, traversal=False):
    config, layer = b'{"os":"linux","architecture":"amd64"}', b'controlled-layer'
    config_info = descriptor(config, 'application/vnd.oci.image.config.v1+json')
    layer_info = descriptor(layer, 'application/vnd.oci.image.layer.v1.tar+gzip')
    manifest = json.dumps({'schemaVersion': 2, 'config': config_info, 'layers': [layer_info]}).encode()
    platform = descriptor(manifest, 'application/vnd.oci.image.manifest.v1+json')
    platform['platform'] = {'os': 'linux', 'architecture': 'amd64'}
    index = json.dumps({'schemaVersion': 2, 'manifests': [platform]}).encode()
    root = descriptor(index, 'application/vnd.oci.image.index.v1+json')
    members = [('index.json', json.dumps({'schemaVersion': 2, 'manifests': [root]}).encode()),
        ('blobs/sha256/' + root['digest'][7:], index),
        ('blobs/sha256/' + platform['digest'][7:], manifest),
        ('blobs/sha256/' + config_info['digest'][7:], config),
        ('blobs/sha256/' + layer_info['digest'][7:], b'corrupted' if bad_blob else layer)]
    if duplicate:
        members.append(members[-1])
    if traversal:
        members.append(('../outside', b'untrusted'))
    with tarfile.open(path, 'w') as archive:
        for name, raw in members:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            if symlink and name.endswith(layer_info['digest'][7:]):
                info.type, info.linkname, info.size = tarfile.SYMTYPE, '/outside', 0
                archive.addfile(info)
            else:
                archive.addfile(info, io.BytesIO(raw))
    return platform, config_info


def test_layout_preserves_manifest_config_and_layer_bytes(tmp_path):
    archive, layout = tmp_path / 'image.tar', tmp_path / 'oci'
    platform, config = image_archive(archive)
    report = samples.oci_layout(archive, layout)
    assert report['platform_digest'] == platform['digest']
    assert report['config_digest'] == config['digest']
    assert json.loads((layout / 'index.json').read_bytes())['manifests'] == [platform]
    assert len(list((layout / 'blobs/sha256').iterdir())) == 3


@pytest.mark.parametrize('option', ['bad_blob', 'duplicate', 'symlink'])
def test_bad_oci_input_is_not_published(tmp_path, option):
    archive = tmp_path / 'image.tar'
    image_archive(archive, **{option: True})
    with pytest.raises(ValueError):
        samples.oci_layout(archive, tmp_path / 'oci')


def test_unreachable_traversal_is_not_extracted(tmp_path):
    archive = tmp_path / 'image.tar'
    image_archive(archive, traversal=True)
    samples.oci_layout(archive, tmp_path / 'oci')
    assert not (tmp_path / 'outside').exists()


def test_layout_and_secret_writes_never_replace(tmp_path):
    archive = tmp_path / 'image.tar'
    image_archive(archive)
    directory = tmp_path / 'existing'
    directory.mkdir()
    with pytest.raises(FileExistsError):
        samples.oci_layout(archive, directory)
    secret = tmp_path / 'token'
    secret.write_bytes(b'preserve')
    with pytest.raises(FileExistsError):
        prepare.exclusive(secret, b'replacement')
    assert secret.read_bytes() == b'preserve'


def test_existing_installation_is_not_reinitialized(tmp_path, monkeypatch):
    monkeypatch.setattr(prepare, 'ROOT', tmp_path)
    monkeypatch.setattr(sys, 'argv', ['prepare_local_mvp.py'])
    (tmp_path / '.env.local-mvp').write_bytes(b'preserve')
    monkeypatch.setattr(prepare.subprocess, 'run', lambda *a, **kw: pytest.fail('No Docker call permitted'))
    with pytest.raises(FileExistsError):
        prepare.main()


def test_cache_seed_does_not_touch_foreign_volume(tmp_path, monkeypatch):
    monkeypatch.setattr(prepare, 'ROOT', tmp_path)
    monkeypatch.setattr(prepare, 'command', lambda *a, **kw: b'[{"Labels":{"owner":"foreign"}}]')
    with pytest.raises(ValueError, match='Only this setup owned volumes'):
        prepare.seed_cache()

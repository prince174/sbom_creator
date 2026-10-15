import io
import json
import tarfile

import pytest
from check_registry_archive_bridge import archive_config, digest


def archive(tmp_path, *, copies=1, platform='amd64', layers=('layer.tar',), oversized=False):
    config = json.dumps({'os': 'linux', 'architecture': platform,
                         'rootfs': {'diff_ids': ['sha256:' + 'a' * 64]}}).encode()
    raw = b' ' * (4 * 1024 * 1024 + 1) if oversized else config
    filename = tmp_path / 'image.tar'
    with tarfile.open(filename, 'w') as output:
        manifest = [{'Config': 'config.json', 'Layers': list(layers)}] * copies
        for name, data in [('config.json', raw), ('manifest.json', json.dumps(manifest).encode())]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            output.addfile(member, io.BytesIO(data))
    return filename, config


def test_binding_uses_raw_config_bytes_and_preserves_diff_ids(tmp_path):
    filename, config = archive(tmp_path)
    config_digest, layers = archive_config(filename)
    assert config_digest == digest(config)
    assert layers == ['sha256:' + 'a' * 64]


@pytest.mark.parametrize('kwargs,message', [
    ({'copies': 2}, 'Ambiguous'),
    ({'platform': 'arm64'}, 'platform'),
    ({'layers': ()}, 'layer count'),
    ({'oversized': True}, 'metadata'),
])
def test_rejects_ambiguous_wrong_platform_and_oversized_metadata(tmp_path, kwargs, message):
    filename, _ = archive(tmp_path, **kwargs)
    with pytest.raises(ValueError, match=message):
        archive_config(filename)

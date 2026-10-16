import json

import pytest

from sbom_creator import image_probe
from sbom_creator.acquire import Settings

SETTINGS = Settings(registry_hosts=('registry.example',))


def test_probe_resolves_immutable_identity_without_full_scan(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv('SBOM_API_TOKEN', 'do-not-pass-service-token')
    monkeypatch.setenv('SBOM_REGISTRY_USERNAME', 'service-user')
    monkeypatch.setenv('SBOM_REGISTRY_PASSWORD', 'do-not-put-password-in-argv')

    def run(args, **kwargs):
        calls.append(args)
        assert 'do-not-put-password-in-argv' not in str(args)
        assert 'SBOM_API_TOKEN' not in kwargs['env']
        assert kwargs['env']['DOCKER_CONFIG'] == str(kwargs['cwd'])
        config = json.loads((kwargs['cwd'] / 'config.json').read_text())
        assert set(config['auths']) == {'registry.example'}
        assert kwargs['max_output_bytes'] == 4096
        return 'v0.22.1' if args[1] == 'version' else 'sha256:' + 'a' * 64

    monkeypatch.setattr(image_probe, 'run_command', run)
    result = image_probe.probe('registry.example/team/app:future', SETTINGS)
    assert result['status'] == 'available'
    assert result['immutable_image'] == 'registry.example/team/app@sha256:' + 'a' * 64
    assert [args[1] for args in calls] == ['version', 'digest']
    assert calls[1] == [SETTINGS.crane_binary, 'digest', 'registry.example/team/app:future']


def test_pinned_index_digest_is_preserved_for_image_platform_selection(monkeypatch):
    digest = 'sha256:' + 'b' * 64
    reference = 'registry.example/team/app@' + digest
    calls = []
    monkeypatch.setattr(image_probe, 'run_command', lambda args, **kw:
        calls.append(args) or ('0.22.1' if args[1] == 'version' else digest))
    result = image_probe.probe(reference, SETTINGS)
    assert result['immutable_image'] == reference
    assert calls[-1] == [SETTINGS.crane_binary, 'digest', reference]


def test_unavailable_is_bounded_unconfirmed_and_does_not_expose_error(monkeypatch):
    def run(args, **kwargs):
        assert kwargs['timeout'] <= SETTINGS.source_image_probe_timeout
        if args[1] == 'version':
            return '0.22.1'
        raise RuntimeError('secret registry credentials and stderr')
    monkeypatch.setattr(image_probe, 'run_command', run)
    result = image_probe.probe('registry.example/app:future', SETTINGS)
    assert result == {'status': 'waiting', 'code': 'REGISTRY_AVAILABILITY_UNCONFIRMED'}
    assert 'secret' not in json.dumps(result)


@pytest.mark.parametrize('image', ['evil.invalid/app:1', 'https://user:pass@registry.example/app:1', 'registry.example/app'])
def test_invalid_reference_does_not_start_tool(image, monkeypatch):
    monkeypatch.setattr(image_probe, 'run_command', lambda *a, **k: pytest.fail('Invalid probe executed'))
    assert image_probe.probe(image, SETTINGS)['status'] == 'failed'


@pytest.mark.parametrize('version', ['latest', '0.22.2', 'private arbitrary output'])
def test_wrong_producer_does_not_probe_registry(version, monkeypatch):
    calls = []
    monkeypatch.setattr(image_probe, 'run_command', lambda args, **kw: calls.append(args) or version)
    assert image_probe.probe('registry.example/app:1', SETTINGS)['code'] == 'REGISTRY_PROBE_TOOL_INVALID'
    assert len(calls) == 1


@pytest.mark.parametrize('digest', ['invalid', 'sha256:' + 'f' * 63, 'sha256:' + 'A' * 64])
def test_invalid_digest_is_not_submitted(digest, monkeypatch):
    monkeypatch.setattr(image_probe, 'run_command', lambda args, **kw: '0.22.1' if args[1] == 'version' else digest)
    assert image_probe.probe('registry.example/app:1', SETTINGS)['status'] == 'failed'


@pytest.mark.parametrize('key', ['source_image_wait_timeout', 'source_image_poll_interval', 'source_image_probe_timeout'])
def test_wait_policy_requires_positive_budget(key):
    with pytest.raises(ValueError):
        Settings(**{key: 0})

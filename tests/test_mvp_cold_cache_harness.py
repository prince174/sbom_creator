"""Cold-cache release probes cannot consume old caches or retry a failed job."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'benchmarks'))
import check_mvp_r111_cold_cache as harness

PINNED = 'sha256:' + 'a' * 64


def command(phase='cold'):
    return harness.container_command(PINNED, Path('/owned/input.tar'), 'new-owned-volume', phase,
        'docker.io/library/fixture@sha256:' + 'b' * 64, 'sha256:' + 'c' * 64,
        {'image_java/java_database_cache.py': 'd' * 64}, 'owned-container')


@pytest.mark.parametrize('image', ['sbom-creator:latest', 'sha256:short', 'sha256:' + 'A' * 64, ''])
def test_mutable_or_invalid_images_cannot_start_a_cold_probe(image):
    with pytest.raises(ValueError, match='Pinned image ID'):
        harness.container_command(image, Path('archive'), 'volume', 'cold', 'reference', 'config', {}, 'name')


@pytest.mark.parametrize('phase', ['retry', 'download', '', '../cold'])
def test_only_one_cold_and_one_warm_phase_are_defined(phase):
    with pytest.raises(ValueError, match='cold/warm'):
        command(phase)


def test_public_network_is_confined_to_cold_and_warm_is_offline():
    assert '--network=bridge' in command('cold')
    assert '--network=none' in command('warm')
    for phase in ('cold', 'warm'):
        args = command(phase)
        for value in ('--pull=never', '--read-only', '--user=10001:10001', '--cap-drop=ALL',
                      '--security-opt=no-new-privileges', '--memory=3g', '--cpus=2', '--pids-limit=128'):
            assert value in args
        mounts = [args[index + 1] for index, value in enumerate(args) if value == '--mount']
        assert mounts == [f'type=bind,src={Path("/owned/input.tar")},dst=/inputs/image.tar,readonly',
                          'type=volume,src=new-owned-volume,dst=/workspace']
        assert '--entrypoint=python' in args
        assert args[args.index('--entrypoint=python') + 1] == PINNED
        assert not any('docker.sock' in value or '/java-db' in value for value in mounts)
        assert '--privileged' not in args and '--rm' not in args


def test_default_release_probe_does_not_supply_reader_overrides_or_credential_env():
    args = command()
    environment = [args[index + 1] for index, value in enumerate(args) if value == '--env']
    assert {item.split('=', 1)[0] for item in environment} == {
        'R111_PHASE', 'R111_IMAGE_REFERENCE', 'R111_EXPECTED_IMAGE_CONFIG', 'R111_EXPECTED_PACKAGE_HASHES'}
    assert not any(item.startswith(('SBOM_JAVA_', 'OPENAI_', 'AWS_', 'GITHUB_', 'HTTP_PROXY'))
                   for item in environment)
    compile(harness.PROGRAM, '<cold-cache-container>', 'exec')
    preflight = harness.preflight_command(PINNED, Path('archive'), 'volume', 'image', 'config', {}, 'owned')
    assert '--network=none' in preflight and '--network=bridge' not in preflight
    assert preflight[-1] == harness.PREFLIGHT
    compile(harness.PREFLIGHT, '<native-cache-preflight>', 'exec')


def test_host_credentials_and_proxy_environment_are_not_forwarded(monkeypatch):
    monkeypatch.setattr(harness.os, 'environ', {'PATH': 'tools', 'SystemRoot': 'windows',
        'USERPROFILE': 'host-docker-context', 'OPENAI_API_KEY': 'secret', 'GITHUB_TOKEN': 'secret',
        'SBOM_REGISTRY_PASSWORD': 'secret', 'HTTPS_PROXY': 'secret', 'DOCKER_HOST': 'untrusted'})
    assert harness.host_environment() == {
        'PATH': 'tools', 'SystemRoot': 'windows', 'USERPROFILE': 'host-docker-context'}


def test_lossless_exports_are_read_back_independently(tmp_path):
    analysis = tmp_path / 'analysis'
    analysis.mkdir()
    (analysis / 'final.cdx.json').write_bytes(b'{"components":[]}\n')
    (analysis / 'audit.json').write_bytes(b'actual-unknown-facts')
    exported = harness.export_analysis(tmp_path)
    assert set(exported) == {'final.cdx.json', 'audit.json'}
    assert all(harness.verify_exports(tmp_path, exported).values())
    exported['audit.json']['original_sha256'] = '0' * 64
    assert harness.verify_exports(tmp_path, exported)['audit.json'] is False


def test_timeout_exports_partial_evidence_before_removing_only_owned_container(tmp_path, monkeypatch):
    events = []

    def run(args, **kwargs):
        events.append(tuple(args[:3]))
        if args[:2] == ['docker', 'run']:
            raise subprocess.TimeoutExpired(args, harness.JOB_SECONDS)
        return subprocess.CompletedProcess(args, 0)

    def copy(name, source, target, environment):
        events.append(('copy', source))
        if source.endswith('environment.json'):
            target.write_text('{}')
        elif source.endswith('result.json'):
            target.write_text('{"status":"failed"}')
        else:
            target.mkdir()
            (target / 'partial-audit.json').write_text('{"status":"partial"}')
        return True

    monkeypatch.setattr(harness.subprocess, 'run', run)
    monkeypatch.setattr(harness, 'copy_from', copy)
    monkeypatch.setattr(harness, 'inspected_container', lambda *_: {'available': False})
    result = harness.run_phase(tmp_path, PINNED, Path('archive'), 'new-volume', 'cold',
        {'image': 'fixture', 'previously_observed_config_digest': 'config'}, {}, {})
    assert result['status'] == 'failed' and result['exit_code'] == 124
    kill = next(index for index, item in enumerate(events) if item[:2] == ('docker', 'kill'))
    copied = next(index for index, item in enumerate(events) if item[0] == 'copy')
    removed = next(index for index, item in enumerate(events) if item[:2] == ('docker', 'rm'))
    assert kill < copied < removed
    assert result['compressed_exports_verified'] == {'partial-audit.json': True}
    assert not any('--force' in event for event in events)


def test_previous_attempt_namespace_is_never_retried(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['probe', '--image', PINNED, '--output', str(tmp_path)])
    monkeypatch.setattr(harness.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('No Docker command allowed'))
    with pytest.raises(FileExistsError, match='Never retry'):
        harness.main()


@pytest.mark.parametrize('preflight_status', ['passed', 'failed'])
def test_failed_preflight_or_cold_job_cannot_start_more_network_work(tmp_path, monkeypatch, preflight_status):
    root = tmp_path / 'repository'
    archive = root / 'benchmarks/.work/paired-commons-dbcp-v1/image.tar'
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b'observed-existing-archive')
    invocation = root / 'benchmarks/results/mvp-r110-held-controls-v1/dbcp/invocation.json'
    invocation.parent.mkdir(parents=True)
    invocation.write_text(json.dumps({'archive': archive.relative_to(root).as_posix(),
        'archive_sha256': harness.sha(archive), 'oracle_read': False,
        'image': 'fixture@sha256:' + 'b' * 64, 'previously_observed_config_digest': 'sha256:' + 'c' * 64}))
    source = root / 'src/sbom_creator'
    source.mkdir(parents=True)
    (source / '__init__.py').write_text('')
    for name in ('Dockerfile', '.dockerignore', 'pyproject.toml'):
        (root / name).write_text('fixture')
    output = root / 'new-attempt'
    monkeypatch.setattr(harness, 'ROOT', root)
    monkeypatch.setattr(sys, 'argv', ['probe', '--image', PINNED, '--output', str(output)])
    monkeypatch.setattr(harness.subprocess, 'check_output',
        lambda *_args, **_kwargs: json.dumps([{'Id': PINNED, 'Config': {'Env': []}}]).encode())
    monkeypatch.setattr(harness.subprocess, 'run', lambda args, **kwargs: subprocess.CompletedProcess(args, 0))
    phases = []

    def run_phase(*args):
        phases.append(args[4])
        return {'status': 'failed'}

    monkeypatch.setattr(harness, 'run_phase', run_phase)
    monkeypatch.setattr(harness, 'run_preflight', lambda *_args: {'status': preflight_status})
    assert harness.main() == 2
    result = json.loads((output / 'report.json').read_bytes())
    if preflight_status == 'passed':
        assert phases == ['cold']
        assert result['warm'] is None
        assert result['network_jobs_started'] == 1
    else:
        assert phases == []
        assert result['status'] == 'failed-native-preflight'
        assert result['network_jobs_started'] == 0
    assert result['network_retry_performed'] is False

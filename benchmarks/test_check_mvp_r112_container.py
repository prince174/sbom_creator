"""Synthetic contracts for the one warm installed check; no Docker calls."""
import ast
import json

import check_mvp_r112_container as harness
import pytest


def test_generated_program_compiles_and_preserves_default_installed_pipeline_checks():
    source = harness.program()
    compile(source, '<warm-installed-program>', 'exec')
    assert "assert phase == 'warm'" in source
    assert "root = pathlib.Path(os.environ['R112_RUN_DIRECTORY'])\nroot.mkdir()" in source
    assert 'installed == json.loads' in source
    assert "assert defaults.java_archive_components is True" in source
    assert "defaults.java_nested_windows is False" in source
    assert "assert 'SBOM_JAVA_ARCHIVE_COMPONENTS' not in os.environ" in source
    assert "analyze(None, None," in source
    assert 'runtime.ensure_database = warm_ensure' in source
    assert "engine['java_database_download_seconds'] == 0" in source
    assert 'database_sha256_before_pipeline=database_before_sha256' in source
    assert 'R111_' not in source


def invocation():
    return {'image': 'docker.io/library/input@sha256:' + 'a' * 64,
            'previously_observed_config_digest': 'sha256:' + 'b' * 64}


def test_command_is_offline_nonroot_readonly_with_program_file_not_quoted_code(tmp_path):
    args = harness.command('sha256:' + 'c' * 64, tmp_path / 'image.tar', tmp_path / 'program.py',
        'sbom-r111-public-java-123', '/workspace/r112-warm-456', invocation(), {'actual.py': 'd' * 64}, 'owned')
    assert args[-2:] == ['sha256:' + 'c' * 64, '/harness/program.py']
    for flag in ('--network=none', '--read-only', '--user=10001:10001', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--memory=3g', '--cpus=2', '--pull=never'):
        assert flag in args
    assert '-c' not in args
    mounts = [args[index + 1] for index, value in enumerate(args) if value == '--mount']
    assert len(mounts) == 3
    assert sum('readonly' in value for value in mounts) == 2
    assert not any('references' in value or 'docker.sock' in value for value in args)
    environment = [args[index + 1] for index, value in enumerate(args) if value == '--env']
    assert not any(value.startswith(('SBOM_', 'OPENAI_', 'AWS_', 'GITHUB_')) for value in environment)
    encoded = next(value.split('=', 1)[1] for value in environment if value.startswith('R112_EXPECTED_PACKAGE_HASHES='))
    assert json.loads(encoded) == {'actual.py': 'd' * 64}
    assert not any('final.cdx' in value or 'selected.syft' in value for value in args)


@pytest.mark.parametrize('image,volume,job', [
    ('mutable:tag', 'sbom-r111-public-java-123', '/workspace/r112-warm-456'),
    ('sha256:' + 'c' * 64, 'unrelated-volume', '/workspace/r112-warm-456'),
    ('sha256:' + 'c' * 64, 'sbom-r111-public-java-123', '/workspace/old-output'),
])
def test_invalid_pinning_or_unowned_job_scope_rejected(image, volume, job, tmp_path):
    with pytest.raises(ValueError):
        harness.command(image, tmp_path / 'image.tar', tmp_path / 'program.py', volume, job,
                        invocation(), {}, 'owned')


def test_download_callback_is_blocked_before_any_download_tool_command():
    tree = ast.parse(harness.GUARD)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('no_download', 'warm_ensure')]
    namespace = {'download_attempts': []}
    namespace['original_ensure'] = lambda cache, downloader: downloader('private-stage')
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<download-guard>', 'exec'), namespace)  # noqa: S102 -- fixed owned guard only
    with pytest.raises(AssertionError, match='downloader callback'):
        namespace['warm_ensure']('cache', lambda *_: pytest.fail('Original downloader must never run'))
    assert namespace['download_attempts'] == ['forbidden']


def test_root_authorization_required_before_any_inputs_or_docker(tmp_path, monkeypatch):
    monkeypatch.setattr('sys.argv', ['harness', '--output', str(tmp_path / 'new')])
    monkeypatch.setattr(harness.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('No Docker'))
    with pytest.raises(ValueError, match='ALL6READY'):
        harness.main()
    assert not (tmp_path / 'new').exists()


def test_existing_attempt_refused_before_prediction_reads_or_docker(tmp_path, monkeypatch):
    monkeypatch.setattr('sys.argv', ['harness', '--root-all-six-ready', '--output', str(tmp_path)])
    monkeypatch.setattr(harness.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('No Docker'))
    with pytest.raises(FileExistsError, match='Preserve'):
        harness.main()

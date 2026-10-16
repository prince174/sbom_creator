"""No Docker/network: contracts for the installed cached-publisher smoke."""
import json

import check_mvp_r113_container as harness
import pytest


def test_program_compiles_and_forbids_scanners_readers_database_and_source_tools():
    compile(harness.PROGRAM, '<owned-installed-program>', 'exec')
    for fragment in ("args[0] == 'convert'", "(payload,'collect')", "(runtime,'peer')",
        "(runtime,'corroborate')", "(java_database_cache,'ensure')", "(scanner,'scan_image')",
        "(pipeline,'resolve_java')", "not pathlib.Path(defaults.trivy_cache_dir).exists()",
        "source['artifacts']", "provenance['source_kind'] == 'not-provided'",
        "len(installed) == 49", "actual == original_payload"):
        assert fragment in harness.PROGRAM
    assert 'selected_ids' not in harness.PROGRAM and 'expected_coordinates' not in harness.PROGRAM


def test_container_receives_only_three_cached_inputs_program_and_empty_native_workspace(tmp_path):
    args = harness.command('sha256:' + 'a' * 64, tmp_path / 'inputs', tmp_path / 'program.py',
        'sbom-r113-publisher-123', {'a.py': 'b' * 64}, {name: 'c' * 64 for name in harness.NAMES}, 'owned')
    assert args[-2:] == ['sha256:' + 'a' * 64, '/harness/program.py']
    assert '--network=none' in args and '--read-only' in args and '--cap-drop=ALL' in args
    assert '--user=10001:10001' in args and '--memory=3g' in args and '--cpus=2' in args
    mounts = [args[index + 1] for index, value in enumerate(args) if value == '--mount']
    assert len(mounts) == 3 and sum('readonly' in mount for mount in mounts) == 2
    assert not any('java-db' in mount or 'docker.sock' in mount or 'references' in mount for mount in mounts)
    environment = [args[index + 1] for index, value in enumerate(args) if value == '--env']
    assert len(environment) == 2 and not any(value.startswith('SBOM_') for value in environment)
    inputs = json.loads(next(value.split('=', 1)[1] for value in environment if value.startswith('R113_INPUT_HASHES=')))
    assert set(inputs) == set(harness.NAMES)


@pytest.mark.parametrize('image,volume', [('mutable:tag', 'sbom-r113-publisher-123'),
    ('sha256:' + 'a' * 64, 'unrelated-volume')])
def test_pinned_image_and_owned_workspace_required(tmp_path, image, volume):
    with pytest.raises(ValueError):
        harness.command(image, tmp_path / 'inputs', tmp_path / 'program', volume, {}, {}, 'owned')


def test_no_root_authorization_cannot_read_host_predictions_or_build(tmp_path, monkeypatch):
    monkeypatch.setattr('sys.argv', ['smoke', '--output', str(tmp_path / 'new')])
    monkeypatch.setattr(harness, 'ready_host', lambda: pytest.fail('No host reads before authorization'))
    with pytest.raises(ValueError, match='READY'):
        harness.main()
    assert not (tmp_path / 'new').exists()


def test_old_attempt_not_overwritten_or_retried(tmp_path, monkeypatch):
    monkeypatch.setattr('sys.argv', ['smoke', '--root-runtime-ready', '--output', str(tmp_path)])
    monkeypatch.setattr(harness, 'ready_host', lambda: pytest.fail('No retry'))
    with pytest.raises(FileExistsError, match='Preserve'):
        harness.main()

"""The DB-update replay cannot acquire sources, replace catalogs or download."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'benchmarks'))
import check_mvp_r112_java as runner


def fixtures(root):
    for pair, previous in runner.CASES.values():
        analysis = root / 'benchmarks/results' / previous / 'analysis'
        analysis.mkdir(parents=True)
        (analysis / 'image-original.syft.json').write_text(json.dumps({
            'descriptor': {'name': 'syft', 'version': '1.51.1'},
            'source': {'type': 'image', 'metadata': {
                'manifestDigest': 'sha256:' + 'a' * 64, 'imageID': 'sha256:' + 'b' * 64}},
            'artifacts': [{'name': 'arbitrary-unfiltered-observed-inventory'}]}))
        (analysis / 'source.syft.json').write_text(json.dumps({
            'descriptor': {'name': 'syft', 'version': '1.51.1'},
            'artifacts': [], 'artifactRelationships': []}))
        archive = root / 'benchmarks/.work' / pair / 'image.tar'
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b'existing-input-only')


def test_fixed_six_inputs_read_only_original_producers_and_empty_source(tmp_path):
    fixtures(tmp_path)
    cases = runner.input_cases(tmp_path)
    assert [case['name'] for case in cases] == list(runner.CASES)
    assert len(cases) == 6
    assert all(case['image'].endswith('@sha256:' + 'a' * 64) for case in cases)
    assert all(case['original_syft_catalog'].name == 'image-original.syft.json' for case in cases)
    assert all('references' not in case['archive'].parts for case in cases)
    assert all('provenance.json' not in str(value) for case in cases for value in case.values())


@pytest.mark.parametrize('field', ['artifacts', 'artifactRelationships'])
def test_nonempty_cached_source_cannot_be_an_image_only_input(tmp_path, field):
    fixtures(tmp_path)
    previous = next(iter(runner.CASES.values()))[1]
    path = tmp_path / 'benchmarks/results' / previous / 'analysis/source.syft.json'
    document = json.loads(path.read_bytes())
    document[field] = [{'unexpected': 'source-or-graph'}]
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='empty source catalog'):
        runner.input_cases(tmp_path)


@pytest.mark.parametrize('field,value', [('name', 'untrusted'), ('version', 'other-version')])
def test_unpinned_producer_is_rejected_before_freeze(tmp_path, field, value):
    fixtures(tmp_path)
    previous = next(iter(runner.CASES.values()))[1]
    path = tmp_path / 'benchmarks/results' / previous / 'analysis/image-original.syft.json'
    document = json.loads(path.read_bytes())
    document['descriptor'][field] = value
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='pinned Syft'):
        runner.input_cases(tmp_path)


def test_missing_archive_does_not_enable_a_registry_fallback(tmp_path):
    fixtures(tmp_path)
    pair = next(iter(runner.CASES.values()))[0]
    (tmp_path / 'benchmarks/.work' / pair / 'image.tar').unlink()
    with pytest.raises(ValueError, match='no acquisition fallback'):
        runner.input_cases(tmp_path)


def test_download_only_command_is_refused_before_process_start():
    with pytest.raises(AssertionError, match='without downloads'):
        runner.offline_peer_command(['trivy', 'image', '--download-java-db-only'])


@pytest.mark.parametrize('removed', ['--input', '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-version-check'])
def test_any_missing_offline_inventory_guard_prevents_process_start(removed):
    args = ['trivy', 'image', '--input', 'existing-image.tar', '--offline-scan',
            '--skip-db-update', '--skip-java-db-update', '--skip-version-check']
    args.remove(removed)
    with pytest.raises(AssertionError, match='offline Trivy'):
        runner.offline_peer_command(args)


def test_version_and_complete_offline_image_command_are_permitted():
    runner.offline_peer_command(['trivy', 'version', '--format', 'json'])
    runner.offline_peer_command(['trivy', 'image', '--input', 'existing-image.tar', '--offline-scan',
        '--skip-db-update', '--skip-java-db-update', '--skip-version-check'])


@pytest.mark.parametrize('field,value', [('java_archive_components', False), ('java_nested_windows', True),
    ('java_image_evidence', False), ('java_backend', 'maven')])
def test_runner_cannot_disguise_a_wrong_release_default(field, value):
    settings = {'java_archive_components': True, 'java_nested_windows': False,
                'java_image_evidence': True, 'java_backend': 'disabled'}
    settings[field] = value
    with pytest.raises(ValueError, match='release defaults'):
        runner.require_release_defaults(SimpleNamespace(**settings))


def test_existing_namespace_refused_before_any_database_or_tool_read(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['runner', '--output', str(tmp_path)])
    monkeypatch.setattr(runner, 'sha', lambda *_: pytest.fail('Existing namespace must fail before input reads'))
    with pytest.raises(FileExistsError, match='Preserve'):
        runner.main()


def test_caller_cannot_substitute_a_reference_or_old_cache(tmp_path, monkeypatch):
    output = tmp_path / 'fresh-output'
    monkeypatch.setattr(sys, 'argv', ['runner', '--output', str(output), '--cache', str(tmp_path / 'other-cache')])
    monkeypatch.setattr(runner, 'sha', lambda *_: pytest.fail('Wrong cache must fail before input reads'))
    with pytest.raises(ValueError, match='separately exported'):
        runner.main()

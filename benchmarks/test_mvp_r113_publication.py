"""Synthetic contracts: no scanner, physical reader, oracle or real publisher."""
import copy
import json

import check_mvp_r113_publication as runner
import pytest


def cached():
    return ({'artifacts': []}, {'source': {'type': 'image'},
        'descriptor': {'name': 'syft', 'version': '1.51.1'}},
        {'source_kind': 'not-provided', 'request': {'repository_url': None, 'commit': None},
         'image': {'payload_evidence': {'a': {'status': 'confirmed', 'payload_kind': 'declared_type_surface'}}}})


def test_exact_two_cases_are_existing_predictions_never_project_or_reference_inputs(tmp_path):
    rows = runner.input_cases(tmp_path)
    assert [row['name'] for row in rows] == ['chalk-original-r106', 'nest-types-r109']
    assert rows[0]['inputs'].as_posix().endswith('paired-chalk-v1/analysis.diagnostics')
    assert rows[0]['baseline'].as_posix().endswith('chalk-publish-diagnostic-v1/analysis')
    assert rows[1]['inputs'] == rows[1]['baseline']
    assert all(path.is_relative_to(tmp_path / 'benchmarks/results')
               for row in rows for key, path in row.items() if key != 'name')


def test_cached_input_check_preserves_actual_payload():
    source, image, provenance = cached()
    original = copy.deepcopy(provenance)
    runner.cached_inputs_valid(source, image, provenance)
    assert provenance == original


@pytest.mark.parametrize('change', ['source', 'repository', 'commit', 'kind', 'directory', 'version', 'payload'])
def test_only_pinned_image_only_catalogs_with_actual_payload_are_eligible(change):
    source, image, provenance = cached()
    if change == 'source':
        source['artifacts'] = [{'id': 'source-project'}]
    elif change in ('repository', 'commit'):
        provenance['request']['repository_url' if change == 'repository' else 'commit'] = 'not-allowed'
    elif change == 'kind':
        provenance['source_kind'] = 'repository'
    elif change == 'directory':
        image['source']['type'] = 'directory'
    elif change == 'version':
        image['descriptor']['version'] = 'other'
    else:
        provenance['image']['payload_evidence'] = None
    with pytest.raises(ValueError, match='cached image-only'):
        runner.cached_inputs_valid(source, image, provenance)


def test_converter_guard_allows_only_convert_and_records_no_other_command():
    calls, delegated = [], []
    def delegate(args, config, *, output):
        delegated.append((args, config, output))
        return 'converted'
    guarded = runner.convert_only(delegate, calls)
    assert guarded(['convert', 'selected.json'], 'config', output='final.json') == 'converted'
    assert calls == ['convert'] and len(delegated) == 1
    for command in ([], ['scan', 'image'], ['version'], ['packages'], ['download-java-db']):
        with pytest.raises(AssertionError):
            guarded(command, 'config', output='never')
    assert calls == ['convert'] and len(delegated) == 1
    with pytest.raises(AssertionError, match='forbids scanning'):
        runner.forbidden()


def test_missing_root_ready_has_no_source_read_or_namespace_side_effect(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, 'input_cases', lambda *_args: calls.append(True))
    monkeypatch.setattr('sys.argv', ['runner', '--output', str(tmp_path / 'unused')])
    with pytest.raises(ValueError, match='READY'):
        runner.main()
    assert not calls and not (tmp_path / 'unused').exists()


def test_existing_attempt_is_never_overwritten_or_resumed(tmp_path, monkeypatch):
    retained = tmp_path / 'previous.txt'
    retained.write_text('preserve exact previous evidence')
    monkeypatch.setattr('sys.argv', ['runner', '--root-source-ready', '--output', str(tmp_path)])
    with pytest.raises(FileExistsError):
        runner.main()
    assert retained.read_text() == 'preserve exact previous evidence'


def test_source_hashes_exclude_generated_cache_and_include_schema(tmp_path):
    (tmp_path / 'schema.json').write_text('{}')
    (tmp_path / 'module.py').write_text('# source\n')
    (tmp_path / '__pycache__').mkdir()
    (tmp_path / '__pycache__/module.pyc').write_bytes(b'not executing')
    assert set(runner.code_hashes(tmp_path)) == {'schema.json', 'module.py'}


def test_coordinate_multiset_retains_os_nested_versions_and_duplicate_instances():
    libc = {'type': 'library', 'name': 'libc', 'version': '1', 'purl': 'pkg:deb/libc@1'}
    original = {'components': [libc, {'name': 'wrapper', 'components': [libc]}]}
    fewer = {'components': [libc, {'name': 'wrapper'}]}
    assert sum(runner.coordinates(original).values()) == 3
    assert runner.coordinates(original) != runner.coordinates(fewer)
    wrong = copy.deepcopy(original)
    wrong['components'][0]['version'] = '2'
    assert runner.coordinates(original) != runner.coordinates(wrong)


def publication_fixture(tmp_path):
    target, baseline = tmp_path / 'target', tmp_path / 'baseline'
    target.mkdir()
    baseline.mkdir()
    payload = {'a': {'status': 'confirmed', 'payload_kind': 'declared_type_surface',
                     'path': '/app/node_modules/lib/index.d.ts'},
               'b': {'status': 'unconfirmed', 'reason': 'unresolved'}}
    components = [{'type': 'library', 'name': 'lib', 'version': '1', 'purl': 'pkg:npm/lib@1'}]
    for folder in (target, baseline):
        for view in runner.VIEWS:
            (folder / (view + '.cdx.json')).write_text(json.dumps({'components': components}))
        (folder / 'selected.syft.json').write_text(json.dumps({'artifacts': [{'id': 'a'}, {'id': 'b'}]}))
    (target / 'provenance.json').write_text(json.dumps({'image': {'payload_evidence': payload}}))
    return target, baseline, payload


def test_all_three_views_ids_and_complete_payload_including_unknown_are_equal(tmp_path):
    target, baseline, payload = publication_fixture(tmp_path)
    validated = []
    result = runner.compare_published(target, baseline, payload, lambda doc: validated.append(doc))
    assert len(validated) == 3 and result['selected_artifact_ids_equal'] is True
    assert result['all_original_payload_facts_equal'] is True and result['declared_type_witness_count'] == 1
    assert all(row['schema_valid'] and row['coordinate_multiset_equal'] for row in result['views'].values())


@pytest.mark.parametrize('change', ['final-version', 'os-duplicate', 'selected-id', 'unknown-payload', 'type-payload'])
def test_cached_publication_cannot_hide_same_count_wrong_version_ids_or_payload(tmp_path, change):
    target, baseline, payload = publication_fixture(tmp_path)
    if change in ('final-version', 'os-duplicate'):
        path = target / ('final.cdx.json' if change == 'final-version' else 'os.cdx.json')
        document = json.loads(path.read_bytes())
        if change == 'final-version':
            document['components'][0]['version'] = '2'
        else:
            document['components'] *= 2
    elif change == 'selected-id':
        path = target / 'selected.syft.json'
        document = {'artifacts': [{'id': 'a'}, {'id': 'different'}]}
    else:
        path = target / 'provenance.json'
        altered = copy.deepcopy(payload)
        altered['b' if change == 'unknown-payload' else 'a']['status'] = 'changed'
        document = {'image': {'payload_evidence': altered}}
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        runner.compare_published(target, baseline, payload, lambda _doc: None)

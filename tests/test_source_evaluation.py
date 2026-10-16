import copy
import hashlib
import json
import os

import pytest

from sbom_creator import source_evaluation as evaluator

COMMIT = 'a' * 40
REPOSITORY = 'https://git.example.test/team/project.git'


def component(name, version='1', *, group='org', kind='maven', ref=None, qualifiers='', subpath=''):
    prefix = f'{group}/' if group else ''
    purl = f'pkg:{kind}/{prefix}{name}' + (f'@{version}' if version else '') + qualifiers + subpath
    result = {'type': 'library', 'name': name, 'bom-ref': ref or purl, 'purl': purl}
    if version:
        result['version'] = version
    if group:
        result['group'] = group
    return result


def document(items=None, *, root=None, dependencies=None):
    items = [component('lib')] if items is None else items
    root = component('app', ref='owner') if root is None else root
    root['type'] = 'application'
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'tools': {'components': [
                {'type': 'application', 'name': 'cdxgen', 'version': '13.4.0'}]}, 'component': root},
            'components': items, 'dependencies': dependencies if dependencies is not None else [
                {'ref': root['bom-ref'], 'dependsOn': [item['bom-ref'] for item in items]}]}


def seal(tmp_path, prediction):
    root = tmp_path / 'source'
    root.mkdir()
    raw = json.dumps(prediction).encode()
    (root / 'source.cdx.json').write_bytes(raw)
    provenance = {'repository_url': REPOSITORY, 'commit': COMMIT, 'requested_commit': COMMIT,
                  'source_sbom_sha256': hashlib.sha256(raw).hexdigest(),
                  'engine': {'name': 'cdxgen', 'version': '13.4.0', 'image_id': 'sha256:' + 'b' * 64}}
    (root / 'source-provenance.json').write_text(json.dumps(provenance))
    (root / 'source-summary.json').write_text(json.dumps({'status': 'completed'}))
    return root


def evaluate(tmp_path, prediction=None, reference=None, **kwargs):
    prediction = document() if prediction is None else prediction
    reference = copy.deepcopy(prediction) if reference is None else reference
    return evaluator.evaluate_source(seal(tmp_path, prediction), reference, scope='build', **kwargs)


def test_nonempty_exact_components_and_direct_graph_measured_without_analyzer(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Post evaluator invoked analyzer')

    monkeypatch.setattr('sbom_creator.source_analysis.analyze_source', forbidden)
    report = evaluate(tmp_path, reference_commit=COMMIT)
    assert report['status'] == 'MEASURED'
    assert not report['image_required'] and not report['analyzer_invoked']
    assert report['reference_binding']['provenance'] == 'caller_asserted_not_attested'
    assert report['reference_binding']['commit_matches_source'] is True
    for view in ('exact_purl', 'coordinates'):
        metrics = report['components'][view]
        assert (metrics['tp'], metrics['fp'], metrics['fn']) == (1, 0, 0)
        assert metrics['precision'] == metrics['recall'] == metrics['f1'] == 1
        assert metrics['exact_version_coverage'] == metrics['matched_version_accuracy'] == 1
        graph = report['direct_dependencies'][view]
        assert (graph['tp'], graph['fp'], graph['fn']) == (1, 0, 0)
        assert graph['inferred_build_declarations'] is False
    json.dumps(report)


@pytest.mark.parametrize(('name', 'group', 'version', 'name_coverage', 'versions'), [
    ('other', 'org', '1', 0, None), ('lib', 'wrong', '1', 0, None),
    ('lib', 'org', '2', 1, 0)])
def test_wrong_name_namespace_or_version_are_not_aliases(tmp_path, name, group, version, name_coverage, versions):
    report = evaluate(tmp_path, document([component(name, version, group=group)]), document())
    for view in ('exact_purl', 'coordinates'):
        metrics = report['components'][view]
        assert (metrics['tp'], metrics['fp'], metrics['fn']) == (0, 1, 1)
        assert metrics['recall'] == metrics['precision'] == metrics['exact_version_coverage'] == 0
        assert metrics['name_coverage'] == name_coverage
        assert metrics['matched_version_accuracy'] == versions


@pytest.mark.parametrize(('qualifiers', 'subpath'), [('?type=jar', ''), ('', '#nested/path')])
def test_qualifier_subpath_differences_remain_visible_alongside_coordinates(tmp_path, qualifiers, subpath):
    report = evaluate(tmp_path, document([component('lib', qualifiers=qualifiers, subpath=subpath)]), document())
    exact, coordinates = report['components']['exact_purl'], report['components']['coordinates']
    assert (exact['tp'], exact['fp'], exact['fn']) == (0, 1, 1)
    assert (coordinates['tp'], coordinates['fp'], coordinates['fn']) == (1, 0, 0)
    assert coordinates['claim'] == 'coordinate_agreement_not_full_package_identity'
    details = coordinates['exact_variant_details'][0]
    assert details['variant_sets_differ'] and details['exact_shared_purls'] == []
    assert len(exact['missing']) == len(exact['extra']) == 1


def test_unknown_prediction_is_known_reference_fn_not_absent_truth(tmp_path):
    unknown = {'type': 'library', 'name': 'lib', 'version': '1', 'bom-ref': 'unknown'}
    report = evaluate(tmp_path, document([unknown]), document())
    metrics = report['components']['exact_purl']
    assert metrics['status'] == 'PARTIAL'
    assert (metrics['tp'], metrics['fp'], metrics['fn']) == (0, 0, 1)
    assert metrics['recall'] == metrics['conservative_precision_including_unknown'] == 0
    assert metrics['predicted_unknown_observations'] == 1
    assert report['direct_dependencies']['exact_purl']['fn'] == 1


def test_reference_unknowns_unscored_but_known_components_still_evaluated(tmp_path):
    reference = document([component('lib'), {'type': 'library', 'name': 'opaque', 'bom-ref': 'opaque'}])
    report = evaluate(tmp_path, reference=reference)
    metrics = report['components']['coordinates']
    assert metrics['status'] == 'PARTIAL' and metrics['tp'] == 1
    assert metrics['reference_unknown_observations'] == 1
    assert metrics['reference_identity_coverage'] == 0.5
    assert metrics['reference_count'] == 1
    graph = report['direct_dependencies']['coordinates']
    assert graph['reference_unknown_observations'] == 1 and graph['reference_count'] == 1


def test_missing_version_keeps_name_coverage_without_claiming_exact_version(tmp_path):
    report = evaluate(tmp_path, document([component('lib', version=None)]), document())
    metrics = report['components']['coordinates']
    assert metrics['name_coverage'] == 1 and metrics['exact_version_coverage'] == 0
    assert metrics['matched_version_accuracy'] is None and metrics['fn'] == 1


def test_contradictory_component_fields_unknown_not_purl_match(tmp_path):
    invalid = component('lib')
    invalid['name'] = 'different'
    report = evaluate(tmp_path, document([invalid]), document())
    assert report['components']['exact_purl']['fn'] == 1
    assert report['components']['exact_purl']['predicted_unknown_observations'] == 1


def test_unscoped_npm_empty_group_and_omitted_group_are_same_components_and_root(tmp_path):
    dependency = component('lib', kind='npm', group=None)
    owner = component('app', kind='npm', group=None, ref='owner')
    reference = document([dependency], root=owner)
    prediction = copy.deepcopy(reference)
    prediction['metadata']['component']['group'] = ''
    prediction['components'][0]['group'] = ''
    report = evaluate(tmp_path, prediction, reference)
    for view in ('exact_purl', 'coordinates'):
        inventory = report['components'][view]
        graph = report['direct_dependencies'][view]
        assert inventory['status'] == graph['status'] == 'MEASURED'
        assert (inventory['tp'], inventory['fp'], inventory['fn']) == (1, 0, 0)
        assert inventory['predicted_unknown_observations'] == 0
        assert (graph['tp'], graph['fp'], graph['fn']) == (1, 0, 0)
        assert graph['predicted_unknown_owners'] == 0


@pytest.mark.parametrize('group', ['', '@wrong'])
def test_scoped_npm_empty_or_wrong_group_is_still_unknown(tmp_path, group):
    dependency = component('lib', kind='npm', group='@scope')
    prediction = document([copy.deepcopy(dependency)])
    prediction['components'][0]['group'] = group
    report = evaluate(tmp_path, prediction, document([dependency]))
    for view in ('exact_purl', 'coordinates'):
        inventory = report['components'][view]
        assert (inventory['tp'], inventory['fp'], inventory['fn']) == (0, 0, 1)
        assert inventory['predicted_unknown_observations'] == 1
        assert report['direct_dependencies'][view]['fn'] == 1


def test_unscoped_npm_nonempty_group_does_not_create_a_namespace_alias(tmp_path):
    dependency = component('lib', kind='npm', group=None)
    prediction = document([copy.deepcopy(dependency)])
    prediction['components'][0]['group'] = 'invented'
    report = evaluate(tmp_path, prediction, document([dependency]))
    assert report['components']['exact_purl']['predicted_unknown_observations'] == 1
    assert report['components']['exact_purl']['fn'] == 1


@pytest.mark.parametrize(('actual', 'reference'), [(document([]), document([])), (document(), document([]))])
def test_empty_reference_never_claims_success_or_100_percent(tmp_path, actual, reference):
    report = evaluate(tmp_path, actual, reference)
    assert report['status'] == 'UNKNOWN'
    for section in ('components', 'direct_dependencies'):
        for metrics in report[section].values():
            assert metrics['status'] == 'UNKNOWN'
            assert metrics['precision'] is None and metrics['recall'] is None
            assert metrics['exact_version_coverage'] is None


@pytest.mark.parametrize('scope', ['runtime', 'unknown'])
def test_cross_scope_source_comparison_not_runtime_precision(tmp_path, scope):
    report = evaluator.evaluate_source(seal(tmp_path, document()), document(), scope=scope)
    assert report['status'] == 'UNKNOWN'
    for section in ('components', 'direct_dependencies'):
        for metrics in report[section].values():
            assert metrics['precision'] is metrics['recall'] is metrics['tp'] is None


def test_missing_predicted_owner_or_graph_keeps_known_reference_edges_fn(tmp_path):
    prediction = document()
    prediction['dependencies'] = []
    report = evaluate(tmp_path, prediction, document())
    assert report['components']['coordinates']['tp'] == 1
    graph = report['direct_dependencies']['coordinates']
    assert graph['status'] == 'UNKNOWN' and (graph['tp'], graph['fn']) == (0, 1)
    assert graph['recall'] == 0 and graph['predicted_graph_unavailable_owners']


def test_missing_reference_graph_remains_unscored(tmp_path):
    reference = document()
    reference['dependencies'] = []
    report = evaluate(tmp_path, reference=reference)
    graph = report['direct_dependencies']['exact_purl']
    assert graph['status'] == 'UNKNOWN' and graph['recall'] is None
    assert graph['reference_graph_unavailable_owners']


def test_nested_module_owners_are_scored_separately_not_global_target_lookup(tmp_path):
    first, second = component('one', ref='one'), component('two', ref='two')
    root = component('app', ref='owner')
    root['components'] = [first, second]
    left, right = component('left'), component('right')
    reference = document([left, right], root=root, dependencies=[
        {'ref': 'owner', 'dependsOn': ['one', 'two']},
        {'ref': 'one', 'dependsOn': [left['bom-ref']]},
        {'ref': 'two', 'dependsOn': [right['bom-ref']]}])
    prediction = copy.deepcopy(reference)
    prediction['dependencies'][1]['dependsOn'] = [right['bom-ref']]
    prediction['dependencies'][2]['dependsOn'] = [left['bom-ref']]
    report = evaluate(tmp_path, prediction, reference)
    assert report['components']['exact_purl']['recall'] == 1
    graph = report['direct_dependencies']['exact_purl']
    assert (graph['tp'], graph['fp'], graph['fn']) == (2, 2, 2)
    assert len(graph['owners']) == 3
    assert graph['inferred_build_declarations'] is False


def test_subject_repeated_under_different_ref_excluded_and_nested_dependency_counted(tmp_path):
    subject = component('app', ref='subject-copy')
    library = component('lib')
    holder = component('holder')
    holder['components'] = [library]
    reference = document([subject, holder])
    report = evaluate(tmp_path, reference=reference, prediction=copy.deepcopy(reference))
    assert report['components']['exact_purl']['reference_count'] == 2
    assert report['components']['exact_purl']['tp'] == 2


@pytest.mark.parametrize('mutation', ['hash', 'commit', 'producer', 'engine', 'summary'])
def test_invalid_source_binding_rejected_without_raw_input(tmp_path, mutation):
    root = seal(tmp_path, document())
    if mutation in ('hash', 'commit', 'engine'):
        path = root / 'source-provenance.json'
        body = json.loads(path.read_text())
        if mutation == 'hash':
            body['source_sbom_sha256'] = '0' * 64
        elif mutation == 'commit':
            body['commit'] = 'not-a-commit-private-token'
        else:
            body['engine']['version'] = 'wrong-private-token'
    elif mutation == 'producer':
        path = root / 'source.cdx.json'
        body = json.loads(path.read_text())
        body['metadata']['tools']['components'][0]['version'] = 'wrong-private-token'
    else:
        path = root / 'source-summary.json'
        body = {'status': 'failed'}
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError) as failure:
        evaluator.evaluate_source(root, document(), 'build')
    assert 'private-token' not in str(failure.value)


def test_caller_commit_must_match_but_is_not_attestation(tmp_path):
    root = seal(tmp_path, document())
    with pytest.raises(ValueError):
        evaluator.evaluate_source(root, document(), 'build', 'c' * 40)
    report = evaluator.evaluate_source(root, document(), 'build')
    assert report['reference_binding']['commit'] is None
    assert report['reference_binding']['scope_attested'] is False


@pytest.mark.parametrize('which', ['source', 'reference'])
def test_dangling_dependency_rejected(tmp_path, which):
    actual, reference = document(), document()
    (actual if which == 'source' else reference)['dependencies'][0]['dependsOn'] = ['missing']
    with pytest.raises(ValueError, match='invalid'):
        evaluator.evaluate_source(seal(tmp_path, actual), reference, 'build')


def test_source_file_budget_enforced(tmp_path, monkeypatch):
    root = seal(tmp_path, document())
    monkeypatch.setattr(evaluator, 'SOURCE_LIMIT', 16)
    with pytest.raises(ValueError):
        evaluator.evaluate_source(root, document(), 'build')


def test_reference_budget_enforced_before_source_read(tmp_path, monkeypatch):
    monkeypatch.setattr('sbom_creator.evaluation.LIMIT', 16)
    with pytest.raises(ValueError):
        evaluator.evaluate_source(tmp_path / 'does-not-exist', document(), 'build')


def test_linked_source_result_rejected(tmp_path):
    root = seal(tmp_path, document())
    original = root / 'source.cdx.json'
    outside = tmp_path / 'outside.json'
    original.rename(outside)
    try:
        original.symlink_to(outside)
    except OSError:
        pytest.skip('Native symlink privilege unavailable')
    with pytest.raises(ValueError):
        evaluator.evaluate_source(root, document(), 'build')


def test_hardlinked_source_result_rejected(tmp_path):
    root = seal(tmp_path, document())
    os.link(root / 'source.cdx.json', tmp_path / 'other-name.json')
    with pytest.raises(ValueError):
        evaluator.evaluate_source(root, document(), 'build')

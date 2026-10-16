"""Synthetic completion/binding contracts; never reads an actual oracle."""
import base64
import copy
import hashlib
import json

import evaluate_local_mvp_api as evaluator
import pytest


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def image_binding():
    config = b'{"rootfs":{"diff_ids":[]}}'
    digest = 'sha256:' + 'a' * 64
    config_digest = 'sha256:' + hashlib.sha256(config).hexdigest()
    sample = {'image': 'registry:5000/test@' + digest,
              'platform_digest': digest, 'config_digest': config_digest}
    provenance = {'source_kind': 'not-provided',
        'request': {'image': sample['image'], 'repository_url': None, 'commit': None},
        'image': {'image_config_digest': config_digest, 'image_digest': digest,
                  'platform_digest': digest, 'container_started': False, 'acquisition': 'registry'}}
    original = {'source': {'type': 'image', 'metadata': {
        'config': base64.b64encode(config).decode()}}}
    return sample, provenance, original


def completed_fixture(tmp_path, monkeypatch):
    workspace = tmp_path / 'workspace/local-mvp'
    sample, provenance, original = image_binding()
    samples = {'status': 'passed', 'foreign_project_built': False, 'samples': {}}
    for name, relative in evaluator.CASES.items():
        folder = workspace / relative
        sample = dict(sample, archive='benchmarks/.work/' + name + '/image.tar',
                      manifest_preserved=True, config_preserved=True,
                      reference_or_source_accessed=False)
        samples['samples'][name] = sample
        views = {view + '.cdx.json': {'bomFormat': 'CycloneDX', 'components': []}
                 for view in evaluator.VIEWS}
        documents = {**views, 'provenance.json': provenance,
            'source.syft.json': {'artifacts': []}, 'image.syft.json': original,
            'summary.json': {'status': 'succeeded'}}
        rows = []
        for filename, document in documents.items():
            write(folder / filename, document)
            rows.append({'name': filename, 'bytes': (folder / filename).stat().st_size,
                         'sha256': evaluator.sha(folder / filename)})
        write(folder / 'client-report.json', {'status': 'succeeded', 'submitted_once': True,
            'partial_artifact': None, 'downloaded_artifacts': rows,
            'elapsed_seconds': 1.0, 'job_id': name})
    write(workspace / 'samples.json', samples)
    monkeypatch.setattr(evaluator, 'archive_platform', lambda *_args: None)
    return workspace


def test_both_clients_gate_artifacts_before_oracle(tmp_path, monkeypatch):
    workspace = tmp_path / 'workspace'
    for name, relative in evaluator.CASES.items():
        write(workspace / relative / 'client-report.json', {
            'status': 'failed' if name == 'javascript-nest' else 'succeeded',
            'submitted_once': True, 'partial_artifact': None})
    with pytest.raises(ValueError, match='Both API clients'):
        evaluator.prepare(tmp_path, workspace, lambda _doc: pytest.fail('Schema read before both complete'))
    assert not (workspace / 'samples.json').exists()


def test_missing_client_does_not_open_reference_or_samples(tmp_path):
    with pytest.raises(ValueError, match='regular artifact'):
        evaluator.prepare(tmp_path, tmp_path / 'missing', lambda _doc: None)


def test_complete_preflight_validates_all_six_views_and_all_seals(tmp_path, monkeypatch):
    workspace = completed_fixture(tmp_path, monkeypatch)
    schemas = []
    prepared, digest = evaluator.prepare(tmp_path, workspace, schemas.append)
    assert len(schemas) == 6 and set(prepared) == set(evaluator.CASES)
    assert digest == evaluator.sha(workspace / 'samples.json')
    assert all(len(row['all_downloaded_artifact_sha256']) == 7 for row in prepared.values())
    assert not (tmp_path / 'benchmarks/references').exists()


@pytest.mark.parametrize('mutation', ['failed', 'partial', 'error', 'duplicate', 'hash', 'size',
                                     'traversal', 'missing_view', 'source', 'summary'])
def test_preflight_rejects_incomplete_or_changed_outputs(tmp_path, monkeypatch, mutation):
    workspace = completed_fixture(tmp_path, monkeypatch)
    folder = workspace / evaluator.CASES['java-rest']
    path = folder / 'client-report.json'
    client = evaluator.read(path)
    if mutation == 'failed':
        client['status'] = 'failed'
    elif mutation == 'partial':
        client['partial_artifact'] = 'final.cdx.json'
    elif mutation == 'error':
        client['error'] = {'code': 'failed'}
    elif mutation == 'duplicate':
        client['downloaded_artifacts'].append(client['downloaded_artifacts'][0])
    elif mutation in ('hash', 'size', 'traversal'):
        key = {'hash': 'sha256', 'size': 'bytes', 'traversal': 'name'}[mutation]
        client['downloaded_artifacts'][0][key] = {'hash': 'a', 'size': -1,
                                                'traversal': '../reference.json'}[mutation]
    elif mutation == 'missing_view':
        client['downloaded_artifacts'] = [row for row in client['downloaded_artifacts']
                                          if row['name'] != 'full.cdx.json']
    else:
        name = 'source.syft.json' if mutation == 'source' else 'summary.json'
        write(folder / name, {'artifacts': [{'id': 'source'}]} if mutation == 'source'
              else {'status': 'failed'})
        for row in client['downloaded_artifacts']:
            if row['name'] == name:
                row.update(sha256=evaluator.sha(folder / name), bytes=(folder / name).stat().st_size)
    write(path, client)
    with pytest.raises(ValueError):
        evaluator.prepare(tmp_path, workspace, lambda _doc: None)


def test_explicit_corrected_attempt_preserves_previous_attempt(tmp_path, monkeypatch):
    workspace = completed_fixture(tmp_path, monkeypatch)
    folder = workspace / evaluator.CASES['java-rest']
    corrected = folder.with_name('java-rest-api-v2')
    folder.rename(corrected)
    write(folder / 'client-report.json', {'status': 'failed'})
    prepared, _digest = evaluator.prepare(tmp_path, workspace, lambda _doc: None,
                                         {'java-rest': corrected})
    assert prepared['java-rest']['analysis'] == corrected
    assert evaluator.read(folder / 'client-report.json') == {'status': 'failed'}


def test_valid_exact_registry_config_binding():
    sample, provenance, original = image_binding()
    evaluator.validate_provenance(provenance, sample, original)


@pytest.mark.parametrize('mutation', ['request', 'digest', 'config', 'platform', 'source',
                                     'execution', 'archive', 'raw_config', 'raw_kind'])
def test_provenance_rejects_forged_or_source_assisted_binding(mutation):
    sample, provenance, original = image_binding()
    if mutation == 'request':
        provenance['request']['image'] = 'other'
    elif mutation == 'digest':
        provenance['image']['image_digest'] = 'sha256:' + 'b' * 64
    elif mutation == 'config':
        provenance['image']['image_config_digest'] = 'sha256:' + 'b' * 64
    elif mutation == 'platform':
        provenance['image']['platform_digest'] = 'sha256:' + 'b' * 64
    elif mutation == 'source':
        provenance['request']['repository_url'] = 'https://source.invalid/project'
    elif mutation == 'execution':
        provenance['image']['container_started'] = True
    elif mutation == 'archive':
        provenance['image']['acquisition'] = 'archive'
    elif mutation == 'raw_config':
        original['source']['metadata']['config'] = '%%'
    else:
        original['source']['type'] = 'directory'
    with pytest.raises(ValueError):
        evaluator.validate_provenance(provenance, sample, original)


def test_coordinate_multiset_preserves_wrong_versions_and_instances():
    component = {'type': 'library', 'name': 'pkg', 'version': '1', 'purl': 'pkg:npm/pkg@1'}
    document = {'components': [component, copy.deepcopy(component)]}
    assert sum(evaluator.coordinates(document).values()) == 2
    document['components'][1]['version'] = '2'
    assert len(evaluator.coordinates(document)) == 2

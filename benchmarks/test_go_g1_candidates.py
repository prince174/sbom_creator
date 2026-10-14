from copy import deepcopy

import pytest
from go_g1_candidates import predict

RAW = b'module example/app\ngo 1.24\nrequire (\nexample/lib v1.0.0\nexample/transitive v2.0.0 // indirect\n)\n'


def image():
    location = [{'path': '/app', 'accessPath': '/app'}]
    owner = {'id': 'a', 'name': 'example/app', 'type': 'go-module', 'metadataType': 'go-module-buildinfo-entry',
             'metadata': {'mainModule': 'example/app', 'goBuildSettings': [
                 {'key': 'vcs.revision', 'value': 'abc'}, {'key': 'vcs.modified', 'value': 'false'}]}, 'locations': location}
    dependency = {'id': 'b', 'name': 'example/lib', 'version': 'v1.0.0', 'metadataType': 'go-module-buildinfo-entry',
                  'metadata': {'mainModule': 'example/app'}, 'locations': deepcopy(location)}
    return {'artifacts': [owner, dependency]}


def test_candidate_is_not_build_import_proof():
    result = predict(RAW, image(), 'abc')
    assert len(result['candidates']) == 1
    assert result['candidates'][0]['direct_edge_proven'] is False
    assert result['excluded_indirect'] == 1


@pytest.mark.parametrize('mutation', ['commit', 'dirty', 'owner', 'duplicate', 'binary', 'version'])
def test_counterexamples(mutation):
    data = image()
    if mutation == 'commit':
        data['artifacts'][0]['metadata']['goBuildSettings'][0]['value'] = 'other'
    elif mutation == 'dirty':
        data['artifacts'][0]['metadata']['goBuildSettings'][1]['value'] = 'true'
    elif mutation == 'owner':
        data['artifacts'][0]['metadata']['mainModule'] = 'other'
    elif mutation == 'duplicate':
        data['artifacts'].append(deepcopy(data['artifacts'][1]))
    elif mutation == 'binary':
        data['artifacts'][1]['locations'][0]['path'] = '/other'
    elif mutation == 'version':
        data['artifacts'][1]['version'] = 'v2.0.0'
    assert predict(RAW, data, 'abc')['candidates'] == []


@pytest.mark.parametrize('extra', [b'replace example/lib => ../lib', b'exclude example/lib v1.0.0', b'toolchain go1.24.1'])
def test_unsupported_manifest_unknown(extra):
    assert predict(RAW + extra, image(), 'abc')['status'] == 'UNKNOWN'

import copy

import pytest
from trivy_payload_bridge import bridge, canonical_path

CONFIG = 'sha256:' + 'a' * 64
LAYER = 'sha256:' + 'b' * 64
OTHER = 'sha256:' + 'c' * 64
VIRTUAL = '/app/root.jar:BOOT-INF/lib/a.jar'


def inputs():
    image = {'source': {'metadata': {'imageID': CONFIG}},
             'files': [{'location': {'path': '/app/root.jar', 'layerID': LAYER},
                        'metadata': {'type': 'RegularFile', 'size': 123}}],
             'artifacts': [{'id': 'a', 'foundBy': 'java-archive-cataloger', 'type': 'java-archive',
                            'purl': 'pkg:maven/incorrect/a@1', 'name': 'a', 'version': '1',
                            'locations': [{'path': '/app/root.jar', 'layerID': LAYER, 'accessPath': VIRTUAL}],
                            'metadata': {'virtualPath': VIRTUAL}}]}
    trivy = {'metadata': {'component': {'properties': [
        {'name': 'aquasecurity:trivy:ImageID', 'value': CONFIG}]}}, 'components': [
            {'type': 'library', 'name': 'a', 'group': 'correct', 'version': '2',
             'purl': 'pkg:maven/correct/a@2', 'bom-ref': 'peer-a', 'properties': [
                 {'name': 'aquasecurity:trivy:FilePath', 'value': 'app/root.jar/BOOT-INF/lib/a.jar'},
                 {'name': 'aquasecurity:trivy:LayerDiffID', 'value': LAYER}]}]}
    witnesses = {'a': {'status': 'confirmed', 'path': VIRTUAL + ':A.class', 'method': 'bounded'}}
    return image, trivy, witnesses


def test_unique_image_layer_path_and_payload_join_preserves_original_inputs():
    image, trivy, witnesses = inputs()
    original = copy.deepcopy((image, trivy, witnesses))
    result, evidence, audit = bridge(image, trivy, witnesses)
    assert result['artifacts'][0]['purl'] == 'pkg:maven/correct/a@2'
    assert result['artifacts'][0]['version'] == '2'
    assert evidence['a']['status'] == 'confirmed'
    assert audit['packages'][0]['original']['purl'] == 'pkg:maven/incorrect/a@1'
    assert (image, trivy, witnesses) == original


@pytest.mark.parametrize('mutate', [
    lambda i, t, w: t['metadata']['component']['properties'][0].update(value=OTHER),
    lambda i, t, w: t['metadata']['component']['properties'].append(t['metadata']['component']['properties'][0]),
])
def test_image_mismatch_or_duplicate_binding_aborts(mutate):
    image, trivy, witnesses = inputs()
    mutate(image, trivy, witnesses)
    with pytest.raises(ValueError, match='Image config'):
        bridge(image, trivy, witnesses)


@pytest.mark.parametrize('mutate', [
    lambda i, t, w: t['components'][0]['properties'][1].update(value=OTHER),
    lambda i, t, w: t['components'][0]['properties'][0].update(value='other/root.jar/BOOT-INF/lib/a.jar'),
    lambda i, t, w: i['files'][0]['location'].update(layerID=OTHER),
    lambda i, t, w: i['files'].append(i['files'][0]),
    lambda i, t, w: i['artifacts'][0]['locations'][0].update(accessPath='/other.jar'),
    lambda i, t, w: t['components'].append(copy.deepcopy(t['components'][0])),
    lambda i, t, w: t['components'][0]['properties'].append(t['components'][0]['properties'][0]),
    lambda i, t, w: t['components'][0].update(version='3'),
    lambda i, t, w: t['components'][0].update(group='wrong'),
    lambda i, t, w: w['a'].update(status='unconfirmed'),
    lambda i, t, w: w['a'].update(path='/app/root.jar:other.jar:A.class'),
])
def test_ambiguous_missing_or_conflicting_evidence_becomes_unknown(mutate):
    image, trivy, witnesses = inputs()
    mutate(image, trivy, witnesses)
    result, evidence, audit = bridge(image, trivy, witnesses)
    assert result['artifacts'][0]['purl'] == image['artifacts'][0]['purl']
    assert evidence['a']['status'] == 'unconfirmed'
    assert audit['packages'][0]['status'] == 'UNKNOWN'


def test_multiple_syft_packages_in_same_archive_are_not_guessed():
    image, trivy, witnesses = inputs()
    second = copy.deepcopy(image['artifacts'][0])
    second['id'] = 'b'
    image['artifacts'].append(second)
    witnesses['b'] = witnesses['a']
    _, evidence, audit = bridge(image, trivy, witnesses)
    assert {entry['status'] for entry in audit['packages']} == {'UNKNOWN'}
    assert all(entry['status'] == 'unconfirmed' for entry in evidence.values())


@pytest.mark.parametrize('value', ['../app.jar', '/app/../bad.jar', '//app/a.jar',
                                  'app\\bad.jar', 'app/a.jar:', 'app//bad.jar', 'app/./bad.jar', 'app/\x00.jar'])
def test_noncanonical_path_never_joins(value):
    with pytest.raises(ValueError):
        canonical_path(value)


def test_non_java_packages_and_witnesses_are_preserved():
    image, trivy, witnesses = inputs()
    npm = {'id': 'npm', 'foundBy': 'javascript-package-cataloger', 'purl': 'pkg:npm/a@1'}
    image['artifacts'].append(npm)
    witnesses['npm'] = {'status': 'confirmed', 'path': '/node_modules/a/index.js'}
    result, evidence, _ = bridge(image, trivy, witnesses)
    assert result['artifacts'][-1] == npm
    assert evidence['npm'] == witnesses['npm']

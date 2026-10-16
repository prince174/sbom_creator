import copy

import pytest
from replay_java_db_peer_r111 import component_instances, image_id


def inventory():
    return {'metadata': {'component': {'properties': [
        {'name': 'aquasecurity:trivy:ImageID', 'value': 'sha256:' + 'a' * 64}]}},
        'components': [{'type': 'library', 'name': 'lib', 'group': 'example',
            'version': '1', 'purl': 'pkg:maven/example/lib@1', 'properties': [
                {'name': 'aquasecurity:trivy:FilePath', 'value': 'app/first.jar'},
                {'name': 'aquasecurity:trivy:LayerDiffID', 'value': 'sha256:' + 'b' * 64}]}]}


def test_peer_multiset_preserves_duplicate_instances_and_ignores_property_order():
    original = inventory()
    reordered = copy.deepcopy(original)
    reordered['components'][0]['properties'].reverse()
    assert component_instances(original) == component_instances(reordered)
    reordered['components'].append(copy.deepcopy(reordered['components'][0]))
    assert component_instances(original) != component_instances(reordered)
    assert sum(component_instances(reordered).values()) == 2


@pytest.mark.parametrize('change', ['version', 'path', 'layer'])
def test_equal_raw_component_count_does_not_mask_wrong_version_path_or_layer(change):
    original, modified = inventory(), inventory()
    if change == 'version':
        modified['components'][0]['version'] = '2'
    else:
        key = 'aquasecurity:trivy:FilePath' if change == 'path' else 'aquasecurity:trivy:LayerDiffID'
        for row in modified['components'][0]['properties']:
            if row['name'] == key:
                row['value'] = 'different'
    assert len(original['components']) == len(modified['components'])
    assert component_instances(original) != component_instances(modified)


def test_unique_image_config_required_for_peer_comparison():
    document = inventory()
    assert image_id(document) == 'sha256:' + 'a' * 64
    document['metadata']['component']['properties'] *= 2
    with pytest.raises(ValueError, match='Unique image config'):
        image_id(document)

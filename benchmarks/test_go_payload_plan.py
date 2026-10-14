import pytest
from go_payload_plan import LIMIT, plan


def inventory(sizes):
    return {'files': [{'location': {'path': path}, 'metadata': {'type': 'RegularFile', 'size': size}}
                      for path, size in sizes.items()]}


def test_boundary_and_aggregate_are_not_silent_truncation():
    assert plan(inventory({'/a': LIMIT}), ['/a'])['status'] == 'PLANNED'
    result = plan(inventory({'/a': LIMIT, '/b': 1}), ['/a', '/b'])
    assert result['reason'] == 'aggregate_binary_budget'
    assert result['paths'] == []
    assert result['unknown_count'] is None


@pytest.mark.parametrize('path', ['/../a', '/a/./b', '/a//b', '/a*', 'relative', '/a\\b'])
def test_literal_paths_only(path):
    assert plan(inventory({path: 1}), [path])['status'] == 'UNKNOWN'


def test_identity_and_type_failures():
    doc = inventory({'/a': 1})
    doc['files'].append(doc['files'][0])
    assert plan(doc, ['/a'])['reason'] == 'ambiguous_file_inventory'
    assert plan(inventory({'/a': True}), ['/a'])['status'] == 'UNKNOWN'
    assert plan(inventory({'/a': 1}), ['/a', '/a'])['status'] == 'UNKNOWN'
    assert plan({}, [[]])['status'] == 'UNKNOWN'

import pytest
from evaluate_trivy_java import owner_edges


def test_owner_edges_ignore_wrapper():
    bom = {'components': [{'bom-ref': 'wrapper'}, {'bom-ref': 'owner', 'purl': 'pkg:maven/g/app@1'},
                           {'bom-ref': 'dep', 'purl': 'pkg:maven/g/lib@2?type=jar'}],
           'dependencies': [{'ref': 'wrapper', 'dependsOn': ['owner']}, {'ref': 'owner', 'dependsOn': ['dep']}]}
    assert owner_edges(bom, ('g', 'app', '1')) == {('g', 'lib', '2')}
    bom['dependencies'].append({'ref': 'owner', 'dependsOn': []})
    with pytest.raises(ValueError, match='ambiguous'):
        owner_edges(bom, ('g', 'app', '1'))

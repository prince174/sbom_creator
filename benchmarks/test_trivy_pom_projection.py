import xml.etree.ElementTree as ET

import pytest
from trivy_optional_projection import NS, project_pom
from trivy_pom_graph import extract


def document():
    return {'components': [
        {'bom-ref': 'wrapper-a', 'type': 'application', 'name': 'a/pom.xml', 'properties': [{'name': 'aquasecurity:trivy:Type', 'value': 'pom'}]},
        {'bom-ref': 'wrapper-b', 'type': 'application', 'name': 'b/pom.xml', 'properties': [{'name': 'aquasecurity:trivy:Type', 'value': 'pom'}]},
        {'bom-ref': 'owner-a', 'type': 'library', 'purl': 'pkg:maven/g/shared@1'},
        {'bom-ref': 'owner-b', 'type': 'library', 'purl': 'pkg:maven/g/shared@1'},
        {'bom-ref': 'dep-a', 'type': 'library', 'purl': 'pkg:maven/g/one@2'},
        {'bom-ref': 'dep-b', 'type': 'library', 'purl': 'pkg:maven/g/two@3'}],
        'dependencies': [{'ref': 'wrapper-a', 'dependsOn': ['owner-a']}, {'ref': 'wrapper-b', 'dependsOn': ['owner-b']},
                         {'ref': 'owner-a', 'dependsOn': ['dep-a']}, {'ref': 'owner-b', 'dependsOn': ['dep-b']}]}


def test_same_purl_contexts_remain_owned_by_exact_source_path():
    rows = extract(document())
    assert rows[0]['direct'] == ['pkg:maven/g/one@2']
    assert rows[1]['direct'] == ['pkg:maven/g/two@3']


@pytest.mark.parametrize('field', ['components', 'dependencies'])
def test_duplicate_references_are_rejected(field):
    value = document()
    value[field].append(value[field][0])
    with pytest.raises(ValueError, match='Duplicate'):
        extract(value)


def test_missing_graph_and_dangling_target_never_become_empty_success():
    value = document()
    value['dependencies'] = value['dependencies'][:-1]
    assert extract(value)[1]['status'] == 'UNKNOWN'
    value['dependencies'][2]['dependsOn'] = ['missing']
    row = extract(value)[0]
    assert row['status'] == 'PARTIAL_UNKNOWN'
    assert row['unknown_targets'] == 1


def test_multiple_wrapper_owners_remain_unknown():
    value = document()
    value['dependencies'][0]['dependsOn'].append('owner-b')
    assert extract(value)[0]['status'] == 'UNKNOWN'


def test_projection_changes_only_unprofiled_direct_optional_flags():
    raw = b'''<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><scope>runtime</scope><optional>true</optional></dependency></dependencies><dependencyManagement><dependencies><dependency><optional>true</optional></dependency></dependencies></dependencyManagement><profiles><profile><dependencies><dependency><optional>true</optional></dependency></dependencies></profile></profiles></project>'''
    transformed, changed = project_pom(raw)
    root = ET.fromstring(transformed)
    assert changed == [('g', 'a')]
    assert root.findtext('m:dependencies/m:dependency/m:optional', namespaces=NS) == 'false'
    assert root.findtext('m:dependencies/m:dependency/m:scope', namespaces=NS) == 'runtime'
    assert root.findtext('m:dependencyManagement/m:dependencies/m:dependency/m:optional', namespaces=NS) == 'true'
    assert root.findtext('m:profiles/m:profile/m:dependencies/m:dependency/m:optional', namespaces=NS) == 'true'


def test_unchanged_projection_preserves_original_bytes():
    raw = b'<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies/></project>'
    assert project_pom(raw) == (raw, [])

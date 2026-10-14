from syft_java_source_baseline import extract


def test_preserves_unspecified_scope_and_edge_orientation():
    owner = {'id': 'a', 'foundBy': 'java-pom-cataloger', 'metadata': {'pomProject': {'artifactId': 'app'}},
             'locations': [{'path': '/pom.xml', 'accessPath': '/pom.xml'}]}
    dep = {'id': 'b', 'version': '2', 'metadata': {'pomProperties': {'groupId': 'g', 'artifactId': 'lib'}}}
    catalog = {'artifacts': [owner, dep], 'artifactRelationships': [{'type': 'dependency-of', 'parent': 'b', 'child': 'a'}]}
    result = extract(catalog, 'pom.xml')
    assert result['rows'][0]['raw_scope'] is None
    assert result['rows'][0]['effective_scope'] is None
    assert result['rows'][0]['retained_by_explicit_scope_filter'] is True
    dep['metadata']['pomProperties']['scope'] = 'test'
    assert extract(catalog, 'pom.xml')['rows'][0]['retained_by_explicit_scope_filter'] is False
    catalog['artifacts'].append(owner)
    assert extract(catalog, 'pom.xml')['status'] == 'UNKNOWN'

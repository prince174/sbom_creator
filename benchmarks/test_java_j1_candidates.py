from java_j1_candidates import predict
from test_java_gav_evidence import artifact
from test_java_local_management import dep, fixture


def test_pipeline_preserves_scope_and_unknown_boundary():
    blobs = fixture(dep('<version>2</version>'), dep())
    source = {'artifacts': [artifact('a', ('g', 'root', '1')), artifact('b', ('g', 'lib', '2'))],
              'artifactRelationships': [{'type': 'dependency-of', 'parent': 'b', 'child': 'a'}]}
    for a in source['artifacts']:
        a['locations'] = [{'path': '/child/pom.xml', 'accessPath': '/child/pom.xml'}]
    result = predict(blobs, 'child/pom.xml', source, source)
    assert len(result['candidates']) == 1
    assert result['candidates'][0]['scope'] == 'compile'
    assert result['candidates'][0]['direct_edge_proven'] is False
    missing = predict(blobs, 'child/pom.xml', source, {'artifacts': []})
    assert missing['unknown_count'] == 1
    assert missing['candidates'] == []
    del blobs['pom.xml']
    blocked = predict(blobs, 'child/pom.xml', source, source)
    assert blocked['status'] == 'UNKNOWN'
    assert blocked['unknown_count'] is None


def test_test_scope_not_promoted_by_image():
    blobs = fixture(dep('<version>2</version><scope>test</scope>'), dep())
    result = predict(blobs, 'child/pom.xml', {'artifacts': []}, {'artifacts': []})
    assert result['candidates'] == []
    assert result['static_model']['rows'][0]['scope'] == 'test'

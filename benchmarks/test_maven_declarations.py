import pytest
from audit_maven_declarations import declarations


def pom(body):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0">' + body + '</project>').encode()


def test_structural_ownership_not_recursive_dependency_search():
    dependency = '<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId></dependency></dependencies>'
    result = declarations(pom(dependency + '<dependencyManagement>' + dependency + '</dependencyManagement>' +
                              '<profiles><profile>' + dependency + '</profile></profiles>' +
                              '<build><plugins><plugin>' + dependency + '</plugin></plugins></build>'))
    assert len(result['dependencies']) == 1
    assert result['management_entries'] == 1
    assert result['profile_dependency_count'] == 1
    assert result['plugin_dependency_count'] == 1
    assert result['dependencies'][0]['effective_scope'] is None


def test_properties_and_scopes_not_resolved():
    result = declarations(pom('<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId>'
                              '<version>${v}</version><scope>provided</scope><optional>true</optional>'
                              '</dependency></dependencies>'))
    row = result['dependencies'][0]
    assert row['property_expression']
    assert row['scope'] == 'provided'
    assert row['optional'] == 'true'
    assert row['resolved_version'] is None


def test_parent_and_modules_are_not_dependency_edges():
    result = declarations(pom('<parent><artifactId>parent</artifactId></parent><modules><module>child</module></modules>'))
    assert result['dependencies'] == []
    assert result['modules'] == ['child']
    assert result['parent_present']
    assert not result['effective_model_complete']


@pytest.mark.parametrize('raw', [b'<!DOCTYPE x><x/>', b'<x/>', b'x' * (1024 * 1024 + 1)], ids=['doctype', 'namespace', 'oversized'])
def test_unsupported_input(raw):
    with pytest.raises(ValueError):
        declarations(raw)

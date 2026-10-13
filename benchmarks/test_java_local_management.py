from java_local_management import project


def pom(body):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>g</groupId>'
            '<artifactId>root</artifactId><version>1</version>' + body + '</project>').encode()


def dep(fields=""):
    return '<dependency><groupId>g</groupId><artifactId>lib</artifactId>' + fields + '</dependency>'


def fixture(managed, declared):
    parent = '<parent><groupId>g</groupId><artifactId>root</artifactId><version>1</version></parent>'
    return {'pom.xml': pom('<dependencyManagement><dependencies>' + managed + '</dependencies></dependencyManagement>'),
            'child/pom.xml': pom(parent + '<dependencies>' + declared + '</dependencies>')}


def test_managed_version_and_scope():
    result = project(fixture(dep('<version>2</version><scope>provided</scope>'), dep()), 'child/pom.xml')
    assert result['rows'][0]['coordinate'] == ['g', 'lib', '2']
    assert result['rows'][0]['scope'] == 'provided'
    assert result['effective_model_proven'] is False


def test_explicit_child_wins():
    result = project(fixture(dep('<version>2</version><scope>provided</scope>'),
                             dep('<version>3</version><scope>test</scope>')), 'child/pom.xml')
    assert result['rows'][0]['coordinate'][-1] == '3'
    assert result['rows'][0]['scope'] == 'test'


def test_management_does_not_create_edge():
    assert project(fixture(dep('<version>2</version>'), ''), 'child/pom.xml')['rows'] == []


def test_import_and_duplicate_unknown():
    for managed in (dep('<version>2</version><scope>import</scope><type>pom</type>'), dep() + dep()):
        assert project(fixture(managed, dep()), 'child/pom.xml')['status'] == 'UNKNOWN'


def test_parent_declarations_not_silently_dropped():
    blobs = fixture('', dep('<version>2</version>'))
    blobs['pom.xml'] = pom('<dependencies>' + dep('<version>3</version>') + '</dependencies>')
    assert project(blobs, 'child/pom.xml')['reason'] == 'inherited_declarations_unsupported'

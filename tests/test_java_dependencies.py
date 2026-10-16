import copy
import json
from pathlib import Path

import pytest

from sbom_creator.acquire import Settings
from sbom_creator.java_evidence import annotate
from sbom_creator.java_inputs import NS, parse, prepare, project, seed_local_poms
from sbom_creator.java_resolver import extract, resolve


def pom(content):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0">' + content + '</project>').encode()


def graph():
    return {'components': [
        {'bom-ref': 'wrapper', 'type': 'application', 'name': 'pom.xml', 'properties': [
            {'name': 'aquasecurity:trivy:Type', 'value': 'pom'}]},
        {'bom-ref': 'owner', 'type': 'library', 'name': 'app', 'version': '1', 'purl': 'pkg:maven/org/app@1'},
        {'bom-ref': 'target', 'type': 'library', 'name': 'lib', 'version': '2', 'purl': 'pkg:maven/org/lib@2'},
    ], 'dependencies': [{'ref': 'wrapper', 'dependsOn': ['owner']},
                        {'ref': 'owner', 'dependsOn': ['target']}, {'ref': 'target', 'dependsOn': []}]}


def trace():
    return [{'path': 'pom.xml', 'sha256': 'test-hash', 'profiles': [], 'declarations': []}]


def test_projection_optional_modules_profiles_and_no_project_execution_inputs(tmp_path):
    raw = pom('<modules><module>child</module></modules><build><plugins><plugin/></plugins></build>'
              '<dependencies><dependency><groupId>org</groupId><artifactId>lib</artifactId>'
              '<version>2</version><optional>true</optional></dependency></dependencies>'
              '<profiles><profile><id>prod</id><dependencies><dependency><groupId>org</groupId>'
              '<artifactId>conditional</artifactId></dependency></dependencies></profile></profiles>')
    projected, declared, profiles = project(raw)
    root = parse(projected)
    assert root.find(NS+'modules') is None and root.find(NS+'build') is None
    assert root.find(NS+'profiles') is None
    assert root.findtext(NS+'dependencies/'+NS+'dependency/'+NS+'optional') == 'false'
    assert declared[0]['optional'] == 'true'
    assert profiles[0]['dependencies'][0]['artifactId'] == 'conditional'
    (tmp_path/'pom.xml').write_bytes(raw)
    destination = tmp_path/'copy'
    prepared = prepare(tmp_path, destination)
    assert (tmp_path/'pom.xml').read_bytes() == raw
    assert prepared[0]['path'] == 'pom.xml'


@pytest.mark.parametrize('raw', [b'<!DOCTYPE x [<!ENTITY y "x">]><project/>',
    b'<project/>', b'<project>\x00</project>', b'\xff\xfe\x00p'])
def test_reject_unsafe_or_unsupported_xml(raw):
    with pytest.raises((ValueError, UnicodeDecodeError)):
        project(raw)


def test_parent_lookup_cannot_escape_sandbox(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'pom.xml').write_bytes(pom('<parent><groupId>x</groupId><artifactId>parent</artifactId>'
                                      '<version>1</version><relativePath>../../../secret.xml</relativePath></parent>'))
    output = tmp_path/'copy'
    prepare(source, output)
    assert parse((output/'pom.xml').read_bytes()).findtext(NS+'parent/'+NS+'relativePath') == '__sbom_missing_parent__.xml'


def test_local_parent_paths_preserved(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'pom.xml').write_bytes(pom('<groupId>org</groupId><artifactId>parent</artifactId><version>1</version>'))
    (source/'child').mkdir()
    (source/'child/pom.xml').write_bytes(pom('<parent><groupId>org</groupId><artifactId>parent</artifactId>'
          '<version>1</version></parent><artifactId>child</artifactId>'))
    output = tmp_path/'copy'
    assert len(prepare(source, output)) == 2
    assert parse((output/'child/pom.xml').read_bytes()).find(NS+'parent/'+NS+'relativePath') is None


def test_maven_parent_directory_path_and_source_only_bom_seed(tmp_path):
    source = tmp_path/'source'
    (source/'parent').mkdir(parents=True)
    (source/'child').mkdir()
    (source/'parent/pom.xml').write_bytes(pom('<groupId>org</groupId><artifactId>parent</artifactId><version>1</version>'))
    (source/'child/pom.xml').write_bytes(pom('<parent><groupId>org</groupId><artifactId>parent</artifactId>'
        '<version>1</version><relativePath>../parent</relativePath></parent><artifactId>child</artifactId>'))
    output, home = tmp_path/'copy', tmp_path/'home'
    prepared = prepare(source, output)
    assert parse((output/'child/pom.xml').read_bytes()).findtext(NS+'parent/'+NS+'relativePath') == '../parent'
    assert len(seed_local_poms(output, home, prepared)) == 2
    cached = home/'.m2/repository/org/child/1/child-1.pom'
    assert parse(cached.read_bytes()).findtext(NS+'parent/'+NS+'relativePath') == '__sbom_missing_parent__.xml'


def test_exact_owner_graph_and_missing_target_keeps_unknown():
    document = graph()
    document['dependencies'][1]['dependsOn'].append('missing')
    rows = extract(document, trace())
    assert rows[0]['owner'] == 'pkg:maven/org/app@1'
    assert [e['status'] for e in rows[0]['edges']] == ['DIRECT', 'UNKNOWN']
    assert rows[0]['edges'][0]['version'] == '2'
    assert rows[0]['edges'][0]['build_usage_proven'] is False


def test_ambiguous_wrapper_or_graph_never_guesses():
    document = graph()
    document['components'].append(copy.deepcopy(document['components'][0]))
    with pytest.raises(ValueError):
        extract(document, trace())
    document = graph()
    document['dependencies'][0]['dependsOn'].append('target')
    assert extract(document, trace())[0]['status'] == 'UNKNOWN'


def test_profile_activation_explicitly_unknown():
    inputs = trace()
    inputs[0]['profiles'] = [{'id': 'prod', 'dependencies': [{'scope': None, 'artifactId': 'conditional'}]}]
    rows = extract(graph(), inputs)
    assert rows[0]['edges'][1]['status'] == 'UNKNOWN'
    assert rows[0]['edges'][1]['profile'] == 'prod'


def test_annotations_do_not_add_unobserved_inventory_or_dangling_edges():
    report = {'edges': extract(graph(), trace())[0]['edges']}
    doc = {'components': []}
    annotate(doc, report)
    assert doc['components'] == [] and 'dependencies' not in doc
    assert report['edges'][0]['status'] == 'DIRECT'
    assert report['edges'][0]['inventory_binding'] == 'UNKNOWN'
    doc = {'components': graph()['components'][1:]}
    annotate(doc, report)
    assert doc['dependencies'] == [{'ref': 'owner', 'dependsOn': ['target']}]
    doc['components'].append(copy.deepcopy(doc['components'][1]))
    doc.pop('dependencies')
    annotate(doc, report)
    assert 'dependencies' not in doc


def test_non_java_does_not_invoke_tool(tmp_path, monkeypatch):
    monkeypatch.setattr('sbom_creator.java_resolver.run_command', lambda *a, **k: pytest.fail('Tool invoked'))
    assert resolve(tmp_path, Settings())['status'] == 'not-applicable'


def test_pinned_isolated_passive_resolver_no_oracle_or_project_execution(tmp_path, monkeypatch):
    (tmp_path/'pom.xml').write_bytes(pom('<artifactId>app</artifactId>'))
    (tmp_path/'.mvn').mkdir()
    (tmp_path/'.mvn/settings.xml').write_text('secret')
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        root = kwargs['cwd']
        assert Path(kwargs['env']['HOME']).is_relative_to(root)
        assert 'SBOM_BITBUCKET_TOKEN' not in kwargs['env']
        assert not list((root/'source').rglob('settings.xml'))
        assert '<mirrorOf>*</mirrorOf>' in (root/'home/.m2/settings.xml').read_text()
        return json.dumps({'Version': '0.75.0'} if 'version' in args else {'bomFormat': 'CycloneDX', **graph()})

    monkeypatch.setattr('sbom_creator.java_resolver.run_command', run)
    report = resolve(tmp_path, Settings())
    assert report['direct_count'] == 1 and report['source_build_executed'] is False
    assert len(calls) == 2 and calls[1][1] == 'fs'


def test_failures_explicit_unknown_without_zero_success(tmp_path, monkeypatch):
    (tmp_path/'pom.xml').write_bytes(pom('<artifactId>app</artifactId>'))
    def fail(*args, **kwargs):
        raise RuntimeError('secret error text')
    monkeypatch.setattr('sbom_creator.java_resolver.run_command', fail)
    report = resolve(tmp_path, Settings())
    assert report['status'] == 'UNKNOWN' and report['unknown_count'] is None
    assert 'secret' not in json.dumps(report)
    assert resolve(tmp_path, Settings(java_maven_repository='http://127.0.0.1/'))['status'] == 'UNKNOWN'

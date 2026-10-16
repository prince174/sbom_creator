import io
import json
import tarfile

import pytest

from sbom_creator import build_backend
from sbom_creator.acquire import Settings
from sbom_creator.build_graph import extract


def project(tmp_path):
    (tmp_path/'pom.xml').write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>org</groupId>'
        '<artifactId>app</artifactId><version>1</version><modules><module>child</module></modules></project>')
    (tmp_path/'child').mkdir()
    (tmp_path/'child/pom.xml').write_text('<project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<groupId>org</groupId><artifactId>child</artifactId><version>1</version></project>')


def bom():
    def component(name, path=None):
        row = {'type': 'application' if path else 'library', 'group': 'org', 'name': name, 'version': '1',
               'purl': 'pkg:maven/org/'+name+'@1', 'bom-ref': name}
        if path:
            row['properties'] = [{'name': 'internal:SrcFile', 'value': 'project/'+path}]
        return row
    root = component('app', 'pom.xml')
    root['components'] = [component('child', 'child/pom.xml')]
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': root, 'tools': {'components': [
                {'type': 'application', 'name': 'cdxgen', 'version': '13.4.0'}]}},
            'components': [component('library')], 'dependencies': [
                {'ref': 'app', 'dependsOn': ['child']}, {'ref': 'child', 'dependsOn': ['library']},
                {'ref': 'library', 'dependsOn': []}]}


def test_native_module_graph_does_not_confuse_containment_with_dependency(tmp_path):
    project(tmp_path)
    result = extract(bom(), tmp_path)
    assert result['direct_count'] == 1
    assert result['edges'][0]['owner_module'] == 'child/pom.xml'
    assert result['edges'][0]['component'] == 'pkg:maven/org/library@1'
    assert result['module_containment'] == [{'owner_ref': 'app', 'module_ref': 'child', 'owner_module': 'pom.xml'}]
    assert result['original_build_reproduced'] is False


def test_explicit_dependency_on_reactor_module_is_retained(tmp_path):
    project(tmp_path)
    path = tmp_path/'pom.xml'
    path.write_text(path.read_text().replace('</project>', '<dependencies><dependency><groupId>org</groupId>'
        '<artifactId>child</artifactId><version>1</version></dependency></dependencies></project>'))
    assert extract(bom(), tmp_path)['direct_count'] == 2


def test_source_archive_is_bounded_regular_and_contains_no_git_configuration(tmp_path, monkeypatch):
    project(tmp_path)
    (tmp_path/'.git').mkdir()
    (tmp_path/'.git/config').write_text('service-secret')
    raw = build_backend.source_archive(tmp_path)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert set(archive.getnames()) == {'pom.xml', 'child/pom.xml'}
        assert all(m.uid == 65532 and m.isfile() for m in archive)
    monkeypatch.setattr(build_backend, 'SOURCE_LIMIT', 20)
    with pytest.raises(ValueError, match='budget'):
        build_backend.source_archive(tmp_path)


def test_job_stdin_transport_has_no_host_mount_or_service_secrets(tmp_path, monkeypatch):
    project(tmp_path)
    calls = []
    monkeypatch.setenv('SBOM_API_TOKEN', 'secret-do-not-pass')

    def run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ['image', 'inspect']:
            return 'sha256:'+'a'*64
        if args[1] == 'run':
            assert '--mount' not in args and '--volume' not in args and '-v' not in args
            assert '--privileged' not in args and '--user=65532:65532' in args
            assert '--pull=never' in args and '--read-only' in args
            assert 'SBOM_API_TOKEN' not in kwargs['env']
            assert kwargs['input_bytes']
            return json.dumps(bom())
        assert args[1:3] == ['rm', '-f']
        return ''

    monkeypatch.setattr(build_backend, 'run_command', run)
    result = build_backend.generate(tmp_path, Settings())
    assert result['direct_count'] == 1
    assert result['engine_image_id'] == 'sha256:'+'a'*64
    assert len(calls) == 3 and calls[1][calls[1].index('--name')+1] == calls[2][-1]


def test_timeout_cleans_only_owned_job(tmp_path, monkeypatch):
    project(tmp_path)
    removed = []
    def run(args, **kwargs):
        if args[1] == 'image':
            return 'sha256:'+'b'*64
        if args[1] == 'run':
            raise RuntimeError('timeout with secret output')
        removed.append(args[-1])
        return ''
    monkeypatch.setattr(build_backend, 'run_command', run)
    with pytest.raises(RuntimeError):
        build_backend.generate(tmp_path, Settings())
    assert len(removed) == 1 and removed[0].startswith('sbom-build-')


def test_cdxgen_failure_falls_back_to_source_resolver_without_blocking_image(tmp_path, monkeypatch):
    def failure(*args):
        raise RuntimeError('private error')
    monkeypatch.setattr(build_backend, 'generate', failure)
    monkeypatch.setattr('sbom_creator.java_resolver.resolve', lambda *args: {
        'status': 'partial', 'edges': [], 'modules': [], 'profile': 'test'})
    result = build_backend.resolve(tmp_path, Settings(java_backend='cdxgen'))
    assert result['selected_backend'] == 'trivy' and result['tree_status'] == 'PARTIAL'
    assert result['image_analysis_blocked'] is False
    assert 'private error' not in json.dumps(result)


def test_both_resolvers_fail_explicit_unknown(tmp_path, monkeypatch):
    def failure(*args):
        raise RuntimeError('private error')
    monkeypatch.setattr(build_backend, 'generate', failure)
    monkeypatch.setattr('sbom_creator.java_resolver.resolve', lambda *args: {
        'status': 'UNKNOWN', 'edges': [], 'modules': [], 'profile': 'test'})
    result = build_backend.resolve(tmp_path, Settings(java_backend='cdxgen'))
    assert result['tree_status'] == 'UNKNOWN' and result['image_analysis_blocked'] is False


def test_native_success_does_not_need_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(build_backend, 'generate', lambda *a: {'status': 'evaluated', 'modules': [], 'edges': []})
    monkeypatch.setattr('sbom_creator.java_resolver.resolve', lambda *a: pytest.fail('Unexpected fallback'))
    assert build_backend.resolve(tmp_path, Settings(java_backend='cdxgen'))['tree_status'] == 'RESOLVED'


def test_disabled_backend_does_not_execute_project_or_resolve_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(build_backend, 'generate', lambda *a: pytest.fail('Disabled backend executed project'))
    monkeypatch.setattr('sbom_creator.java_resolver.resolve', lambda *a: pytest.fail('Disabled backend resolved metadata'))
    result = build_backend.resolve(tmp_path, Settings())
    assert result == {'status': 'not-applicable', 'profile': 'java-disabled', 'edges': []}

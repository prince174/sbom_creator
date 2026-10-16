import io
import json
import tarfile

import pytest

from sbom_creator import source_analysis as source
from sbom_creator.acquire import Settings

COMMIT = 'a' * 40
REPOSITORY = 'https://git.example.test/team/project.git'
IMAGE_ID = 'sha256:' + 'b' * 64


def bom(kind='maven'):
    name = 'org/lib' if kind == 'maven' else 'lib'
    purl = f'pkg:{kind}/{name}@1.0.0'
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'tools': {'components': [
                {'type': 'application', 'name': 'cdxgen', 'version': '13.4.0'}]},
                'component': {'type': 'application', 'name': 'project', 'bom-ref': 'owner'}},
            'components': [{'type': 'library', 'name': 'lib', 'version': '1.0.0',
                            'purl': purl, 'bom-ref': purl}],
            'dependencies': [{'ref': 'owner', 'dependsOn': [purl]}, {'ref': purl, 'dependsOn': []}]}


@pytest.fixture
def settings():
    return Settings(bitbucket_hosts=('git.example.test',), java_backend='disabled')


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    calls = []
    state = {'manifest': 'pom.xml', 'document': bom(), 'commit': COMMIT}

    def checkout(repository, commit, destination, settings):
        assert repository == REPOSITORY and commit == COMMIT
        assert not destination.exists()
        destination.mkdir()
        (destination / state['manifest']).write_text('{}')
        (destination / '.git').mkdir()
        (destination / '.git/config').write_text('service-managed-git-secret')
        return {'repository_url': repository, 'requested_commit': commit, 'commit': state['commit'],
                'checkout_method': 'git-init-fetch-exact-detached', 'coverage': {}}

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if args[1:3] == ['image', 'inspect']:
            return IMAGE_ID
        if args[1] == 'run':
            return json.dumps(state['document'])
        assert args[1:3] == ['rm', '-f']
        return ''

    monkeypatch.setattr(source, 'checkout', checkout)
    monkeypatch.setattr(source, 'run_command', run)
    return state, calls


@pytest.mark.parametrize(('manifest', 'kind', 'expected'), [
    ('pom.xml', 'maven', 'java'), ('build.gradle.kts', 'maven', 'java'),
    ('package.json', 'npm', 'js')])
def test_source_runs_when_java_backend_disabled_without_image(tmp_path, settings, runtime, manifest, kind, expected):
    state, calls = runtime
    state.update(manifest=manifest, document=bom(kind))
    output = tmp_path / 'published'
    result = source.analyze_source(REPOSITORY, COMMIT, output, settings=settings)
    assert result['status'] == 'completed'
    assert {path.name for path in output.iterdir()} == set(source.ARTIFACTS)
    document = json.loads((output / 'source.cdx.json').read_text())
    assert document == state['document']  # Preserve the exact emitted graph; no manufactured edges.
    summary = result['summary']
    assert summary['dependency_edges'] == 1 and summary['components'] == 1
    assert summary['project_types'] == [expected]
    assert summary['image_presence_verified'] is False
    provenance = json.loads((output / 'source-provenance.json').read_text())
    assert provenance['commit'] == COMMIT and provenance['repository_url'] == REPOSITORY
    assert provenance['original_build_reproduced'] is False
    assert provenance['reference_used_as_input'] is False
    assert provenance['image_input_used'] is False
    assert provenance['engine']['image_id'] == IMAGE_ID
    assert len(calls) == 3
    assert f'-t {expected}' in calls[1][0][-1]


def test_job_transports_only_regular_source_stdin_not_host_secrets(tmp_path, settings, runtime, monkeypatch):
    monkeypatch.setenv('SBOM_API_TOKEN', 'do-not-pass')
    monkeypatch.setenv('SBOM_REGISTRY_PASSWORD', 'registry-secret')
    monkeypatch.setenv('SBOM_BITBUCKET_TOKEN', 'git-secret')
    monkeypatch.setenv('DOCKER_HOST', 'unix:///service-coordinator.sock')
    _, calls = runtime
    source.analyze_source(REPOSITORY, COMMIT, tmp_path / 'out', settings=settings)
    args, options = calls[1]
    assert '--mount' not in args and '-v' not in args and '--volume' not in args
    assert '--privileged' not in args and '--read-only' in args
    assert '--user=65532:65532' in args and '--cap-drop=ALL' in args
    assert '--pull=never' in args and '--memory=3g' in args and '--pids-limit=256' in args
    assert '--security-opt=no-new-privileges' in args
    assert 'GRADLE_USER_HOME=/tmp/home/.gradle' in args
    for proxy in ('HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'NO_PROXY', 'ALL_PROXY'):
        assert proxy + '=' in args and proxy.lower() + '=' in args
    assert options['timeout'] == settings.build_timeout
    assert options['max_output_bytes'] == settings.max_sbom_bytes
    assert 'SBOM_API_TOKEN' not in options['env']
    assert 'SBOM_REGISTRY_PASSWORD' not in options['env']
    assert 'SBOM_BITBUCKET_TOKEN' not in options['env']
    assert options['env']['DOCKER_HOST'] == 'unix:///service-coordinator.sock'
    assert 'unix:///service-coordinator.sock' not in args
    with tarfile.open(fileobj=io.BytesIO(options['input_bytes'])) as archive:
        assert archive.getnames() == ['pom.xml']
        assert all(member.isfile() and member.uid == 65532 for member in archive)
    assert calls[2][0][-1] == args[args.index('--name') + 1]


@pytest.mark.parametrize('mutate', [
    lambda document: document['metadata']['tools']['components'][0].update(version='13.3.0'),
    lambda document: document['metadata']['tools'].update(components=[]),
    lambda document: document['metadata']['tools']['components'].append(
        {'type': 'application', 'name': 'cdxgen', 'version': '13.4.0'}),
    lambda document: document.update(components=[]),
    lambda document: document['dependencies'][0].update(dependsOn=['invented']),
    lambda document: document.update(specVersion='1.7'),
])
def test_invalid_result_never_published(tmp_path, settings, runtime, mutate):
    state, _ = runtime
    mutate(state['document'])
    output = tmp_path / 'out'
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, output, settings=settings)
    assert failure.value.stage == 'source_validation' and failure.value.code == 'SOURCE_INVALID_RESULT'
    assert not output.exists()


def test_duplicate_json_keys_rejected():
    with pytest.raises(ValueError, match='Duplicate'):
        source._validate_result('{"components":[],"components":[]}')


def test_unsupported_project_never_starts_engine(tmp_path, settings, runtime):
    state, calls = runtime
    state['manifest'] = 'requirements.txt'
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, tmp_path / 'out', settings=settings)
    assert failure.value.code == 'SOURCE_UNSUPPORTED' and calls == []


def test_checkout_mismatch_and_raw_failure_never_escape(tmp_path, settings, runtime):
    state, calls = runtime
    state['commit'] = 'c' * 40
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, tmp_path / 'out', settings=settings)
    assert failure.value.stage == 'source_checkout' and calls == []
    assert 'mismatch' not in str(failure.value)


@pytest.mark.parametrize('bad_input', ['http://git.example.test/a.git', 'https://secret:password@git.example.test/a.git'])
def test_source_input_validation_precedes_checkout(tmp_path, settings, runtime, bad_input):
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(bad_input, COMMIT, tmp_path / 'out', settings=settings)
    assert failure.value.code == 'SOURCE_CHECKOUT_FAILED'
    assert 'password' not in str(failure.value)


def test_timeout_cleans_only_owned_job_and_hides_logs(tmp_path, settings, runtime, monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == 'image':
            return IMAGE_ID
        if args[1] == 'run':
            raise RuntimeError('secret log /private/path timed out')
        assert args[1:3] == ['rm', '-f']
        return ''

    monkeypatch.setattr(source, 'run_command', run)
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, tmp_path / 'out', settings=settings)
    assert failure.value.code == 'SOURCE_ENGINE_FAILED'
    assert 'secret' not in str(failure.value) and '/private' not in str(failure.value)
    assert calls[-1][-1] == calls[1][calls[1].index('--name') + 1]
    assert calls[-1][-1].startswith('sbom-source-')


def test_existing_output_never_modified_or_engine_started(tmp_path, settings, runtime):
    output = tmp_path / 'out'
    output.mkdir()
    marker = output / 'keep'
    marker.write_text('owned output')
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, output, settings=settings)
    assert failure.value.stage == 'source_publication'
    assert marker.read_text() == 'owned output' and runtime[1] == []


def test_partial_publication_and_racing_destination_preserve_original(tmp_path, settings, runtime, monkeypatch):
    output = tmp_path / 'out'

    def fail_commit(staged, destination):
        assert {p.name for p in staged.iterdir()} == set(source.ARTIFACTS)
        destination.mkdir()
        (destination / 'keep').write_text('racing owner')
        raise FileExistsError('private output path')

    monkeypatch.setattr(source, 'commit_directory', fail_commit)
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, output, settings=settings)
    assert failure.value.code == 'SOURCE_PUBLICATION_FAILED'
    assert list(output.iterdir()) == [output / 'keep']
    assert not list(tmp_path.glob('.source-publish-*'))


def test_write_failure_never_exposes_incomplete_output(tmp_path, settings, runtime, monkeypatch):
    original = source._write

    def write(path, document):
        if path.name == 'source-summary.json':
            raise PermissionError('secret path')
        original(path, document)

    monkeypatch.setattr(source, '_write', write)
    with pytest.raises(source.SourceAnalysisError):
        source.analyze_source(REPOSITORY, COMMIT, tmp_path / 'out', settings=settings)
    assert not (tmp_path / 'out').exists() and not list(tmp_path.glob('.source-publish-*'))


def test_publication_cleanup_fault_does_not_invalidate_committed_output(tmp_path, monkeypatch):
    original = source.tempfile.TemporaryDirectory

    class CleanupDenied:
        def __init__(self, **kwargs):
            self.actual = original(**kwargs)
            self.name = self.actual.name

        def cleanup(self):
            self.actual.cleanup()
            raise PermissionError('private cleanup path')

    monkeypatch.setattr(source.tempfile, 'TemporaryDirectory', CleanupDenied)
    output = tmp_path / 'out'
    assert source._publish(output, bom(), {}, {}) is False
    assert {p.name for p in output.iterdir()} == set(source.ARTIFACTS)


def test_publication_cleanup_fault_does_not_mask_first_failure(tmp_path, monkeypatch):
    original = source.tempfile.TemporaryDirectory

    class CleanupDenied:
        def __init__(self, **kwargs):
            self.actual = original(**kwargs)
            self.name = self.actual.name

        def cleanup(self):
            self.actual.cleanup()
            raise PermissionError('secondary error')

    def write(*args):
        raise ValueError('original error')

    monkeypatch.setattr(source.tempfile, 'TemporaryDirectory', CleanupDenied)
    monkeypatch.setattr(source, '_write', write)
    with pytest.raises(ValueError, match='original error'):
        source._publish(tmp_path / 'out', bom(), {}, {})


def test_two_languages_are_passed_without_project_type_guess(tmp_path):
    (tmp_path / 'pom.xml').write_text('')
    (tmp_path / 'web').mkdir()
    (tmp_path / 'web/package.json').write_text('{}')
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules/pom.xml').write_text('')
    assert source._project_types(tmp_path) == ['java', 'js']


def test_tracked_build_and_target_modules_reach_engine_with_legacy_archive_defaults_unchanged(tmp_path):
    from sbom_creator.build_backend import source_archive

    (tmp_path / 'build').mkdir()
    (tmp_path / 'build/pom.xml').write_text('<project/>')
    (tmp_path / 'target').mkdir()
    (tmp_path / 'target/package.json').write_text('{}')
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git/config').write_text('private checkout transport configuration')
    assert source._project_types(tmp_path) == ['java', 'js']
    with tarfile.open(fileobj=io.BytesIO(source_archive(tmp_path))) as archive:
        assert archive.getnames() == []  # Existing Java backend behavior stays frozen.
    raw = source_archive(tmp_path, excluded_directories=source.IGNORED_DIRECTORIES)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert archive.getnames() == ['build/pom.xml', 'target/package.json']


def test_source_archive_rejects_regular_file_budget(tmp_path, settings, runtime, monkeypatch):
    monkeypatch.setattr('sbom_creator.build_backend.SOURCE_LIMIT', 1)
    with pytest.raises(source.SourceAnalysisError) as failure:
        source.analyze_source(REPOSITORY, COMMIT, tmp_path / 'out', settings=settings)
    assert failure.value.code == 'SOURCE_ENGINE_FAILED' and runtime[1] == []


def test_no_image_and_no_reference_contract():
    import inspect
    assert list(inspect.signature(source.analyze_source).parameters) == [
        'repository_url', 'commit', 'output', 'settings']
    assert not {'image', 'reference', 'image_archive'} & source.analyze_source.__annotations__.keys()

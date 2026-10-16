"""Deterministic storage faults; synthetic catalogs, no scanner or accuracy claim."""
import copy
import errno
import json
from pathlib import Path

import pytest

from sbom_creator import pipeline, publication
from sbom_creator.acquire import Settings

SECRET = 'private-token-and-path-must-not-be-exported'


def catalog():
    return {'artifacts': [], 'artifactRelationships': [], 'files': [], 'distro': {},
        'source': {'id': 'synthetic-input', 'name': 'empty-contract-fixture', 'version': '',
                   'type': 'directory', 'metadata': {}},
        'descriptor': {'name': 'syft', 'version': '1.51.1'},
        'schema': {'version': '16.1.10', 'url': 'https://example.invalid/syft-schema'}}


@pytest.fixture
def publisher(tmp_path, monkeypatch):
    def convert(_source, output, _settings):
        document = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                    'components': [], 'dependencies': []}
        output.write_text(json.dumps(document), encoding='utf-8')
        return document
    monkeypatch.setattr(pipeline, 'convert', convert)

    def run(name='result'):
        return pipeline.publish_catalogs(catalog(), catalog(), tmp_path / name,
            Settings(), pipeline.rules_assessor, {'source_kind': 'synthetic-contract-test'})
    return run


def in_staging(path):
    return any(part.startswith('.publish-') for part in path.parts)


def details(failure, operation, *, artifact=None, committed=False, code='PUBLICATION_PERMISSION_DENIED'):
    error = failure.value
    assert type(error) is pipeline.AnalysisError
    assert error.stage == 'reconcile_convert_validate'
    fields = pipeline.publication_details(error)
    assert fields['publication_operation'] == operation
    assert fields['publication_error_code'] == code
    assert fields['publication_committed'] is committed
    if artifact is not None:
        assert fields['publication_artifact'] == artifact
    assert SECRET not in str(error) + json.dumps(fields)
    return fields


def failure_record(tmp_path):
    record = json.loads((tmp_path / 'result.diagnostics/failure.json').read_bytes())
    for path in (tmp_path / 'result.diagnostics').iterdir():
        if path.is_file():
            assert SECRET not in path.read_text('utf-8')
    return record


@pytest.mark.parametrize('artifact', ['full.cdx.json', 'os.cdx.json', 'final.cdx.json'])
def test_json_write_denial_has_exact_artifact_and_no_partial_published_views(publisher, tmp_path, monkeypatch, artifact):
    original = Path.write_text
    def denied(path, *args, **kwargs):
        if in_staging(path) and path.name == artifact + '.tmp':
            raise PermissionError(errno.EACCES, SECRET)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'write_text', denied)
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    fields = details(caught, 'write_artifact', artifact=artifact)
    assert fields['publication_os_error'] == 'access_denied'
    assert fields['diagnostics_status'] == 'complete'
    assert failure_record(tmp_path)['final_published'] is False
    assert not (tmp_path / 'result').exists()
    assert not list(tmp_path.glob('.publish-*'))


def test_converter_partial_output_never_becomes_a_published_final(publisher, tmp_path, monkeypatch):
    def denied(_source, output, _settings):
        output.write_bytes(b'partial converter bytes')
        raise PermissionError(errno.EACCES, SECRET)
    monkeypatch.setattr(pipeline, 'convert', denied)
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    details(caught, 'convert_final', artifact='final.cdx.json')
    record = failure_record(tmp_path)
    assert record['error_type'] == 'PermissionError' and record['final_published'] is False
    assert not (tmp_path / 'result').exists()
    assert not list(tmp_path.glob('.publish-*'))


def test_commit_directory_denial_is_separate_from_converter_and_writes(publisher, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, 'commit_directory', lambda *_: (_ for _ in ()).throw(PermissionError(errno.EACCES, SECRET)))
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    details(caught, 'commit_directory')
    assert failure_record(tmp_path)['final_published'] is False
    assert not (tmp_path / 'result').exists()
    assert not list(tmp_path.glob('.publish-*'))


@pytest.mark.parametrize('nonempty', [False, True])
def test_racing_output_is_never_replaced_and_not_claimed_as_our_commit(publisher, tmp_path, monkeypatch, nonempty):
    real_commit = pipeline.commit_directory
    captured = []
    def raced(source, destination):
        destination.mkdir()
        if nonempty:
            (destination / 'foreign-sentinel').write_bytes(b'previous owner')
        captured.append(destination.stat().st_ino)
        real_commit(source, destination)
    monkeypatch.setattr(pipeline, 'commit_directory', raced)
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    fields = details(caught, 'commit_directory', code='PUBLICATION_OUTPUT_CONFLICT')
    assert fields['publication_os_error'] in {'file_exists', 'unspecified'}
    destination = tmp_path / 'result'
    assert destination.stat().st_ino == captured[0]
    assert {p.name for p in destination.iterdir()} == ({'foreign-sentinel'} if nonempty else set())
    assert failure_record(tmp_path)['final_published'] is False


def test_preexisting_complete_output_fails_before_new_work_without_diagnostic_overwrite(publisher, tmp_path, monkeypatch):
    destination = tmp_path / 'result'
    destination.mkdir()
    (destination / 'final.cdx.json').write_bytes(b'preserve prior verified result')
    monkeypatch.setattr(pipeline, 'validate_syft', lambda *_: pytest.fail('Existing output must fail before validation'))
    with pytest.raises(FileExistsError):
        publisher()
    assert (destination / 'final.cdx.json').read_bytes() == b'preserve prior verified result'
    assert not (tmp_path / 'result.diagnostics').exists()


def failing_converter(*_args):
    raise RuntimeError(SECRET)


def test_unavailable_diagnostics_do_not_mask_original_converter_error(publisher, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, 'convert', failing_converter)
    monkeypatch.setattr(pipeline, 'diagnostic', lambda *_: (_ for _ in ()).throw(PermissionError(errno.EACCES, SECRET)))
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    fields = details(caught, 'convert_final', artifact='final.cdx.json', code='PUBLICATION_FAILED')
    assert caught.value.error_type == 'RuntimeError'
    assert fields['diagnostics_status'] == 'unavailable'
    assert fields['diagnostics_error_code'] == 'PUBLICATION_PERMISSION_DENIED'
    assert not (tmp_path / 'result').exists()


def test_partial_diagnostics_keep_first_error_and_rewrite_safe_failure_record(publisher, tmp_path, monkeypatch):
    original = pipeline.write_json
    def denied(path, data):
        if path.parent.name == 'result.diagnostics' and path.name == 'source.syft.json':
            raise OSError(errno.ENOSPC, SECRET)
        return original(path, data)
    monkeypatch.setattr(pipeline, 'convert', failing_converter)
    monkeypatch.setattr(pipeline, 'write_json', denied)
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    fields = details(caught, 'convert_final', artifact='final.cdx.json', code='PUBLICATION_FAILED')
    assert caught.value.error_type == 'RuntimeError'
    assert fields['diagnostics_status'] == 'partial'
    assert fields['diagnostics_error_code'] == 'PUBLICATION_IO_ERROR'
    record = failure_record(tmp_path)
    assert record['error_type'] == 'RuntimeError' and record['diagnostics_status'] == 'partial'


def cleanup_fault(monkeypatch, prefix, error):
    original = publication.tempfile.TemporaryDirectory.cleanup
    def failing(temporary):
        original(temporary)
        if Path(temporary.name).name.startswith(prefix):
            raise error
    monkeypatch.setattr(publication.tempfile.TemporaryDirectory, 'cleanup', failing)


def test_cleanup_secondary_error_preserves_primary_converter_fault(publisher, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, 'convert', failing_converter)
    cleanup_fault(monkeypatch, '.publish-', OSError(errno.ENOSPC, SECRET))
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    fields = details(caught, 'convert_final', artifact='final.cdx.json', code='PUBLICATION_FAILED')
    assert caught.value.error_type == 'RuntimeError'
    assert fields['cleanup_error_code'] == 'PUBLICATION_IO_ERROR'
    assert failure_record(tmp_path)['error_type'] == 'RuntimeError'


def test_cleanup_after_commit_truthfully_marks_complete_output_but_returns_failure(publisher, tmp_path, monkeypatch):
    cleanup_fault(monkeypatch, '.publish-', PermissionError(errno.EACCES, SECRET))
    with pytest.raises(pipeline.AnalysisError) as caught:
        publisher()
    fields = details(caught, 'cleanup_staging', committed=True)
    assert 'publication_artifact' not in fields
    assert {path.name for path in (tmp_path / 'result').iterdir()} == set(pipeline.ARTIFACTS)
    assert failure_record(tmp_path)['final_published'] is True
    assert not list(tmp_path.glob('.publish-*'))


def test_outer_workspace_cleanup_does_not_mask_typed_publication_error(monkeypatch):
    cleanup_fault(monkeypatch, 'sbom-job-', PermissionError(errno.EACCES, SECRET))
    primary = pipeline.AnalysisError('reconcile_convert_validate', 'ValueError', publication={
        'publication_operation': 'validate_final', 'publication_error_code': 'PUBLICATION_INVALID_DATA',
        'publication_committed': False, 'diagnostics_status': 'complete'})
    with pytest.raises(pipeline.AnalysisError) as caught, pipeline._analysis_temporary_directory():
        raise primary
    assert caught.value is primary and caught.value.error_type == 'ValueError'
    assert pipeline.publication_details(primary)['workspace_cleanup_error_code'] == 'PUBLICATION_PERMISSION_DENIED'
    assert SECRET not in str(primary) + json.dumps(primary.publication)


@pytest.mark.parametrize('failures', [0, 2, 19, 20])
def test_atomic_json_replace_retries_permission_denial_only_and_is_bounded(tmp_path, monkeypatch, failures):
    path = tmp_path / 'status.json'
    path.write_bytes(b'{"state":"prior"}')
    real_replace, attempts, sleeps = Path.replace, [], []
    def replace(source, destination):
        attempts.append(source)
        assert json.loads(path.read_bytes()) == {'state': 'prior'}
        if len(attempts) <= failures:
            raise PermissionError(errno.EACCES, SECRET)
        return real_replace(source, destination)
    monkeypatch.setattr(Path, 'replace', replace)
    monkeypatch.setattr(pipeline.time, 'sleep', sleeps.append)
    if failures == 20:
        with pytest.raises(PermissionError):
            pipeline.write_json(path, {'state': 'next'})
        assert json.loads(path.read_bytes()) == {'state': 'prior'}
    else:
        pipeline.write_json(path, {'state': 'next'})
        assert json.loads(path.read_bytes()) == {'state': 'next'}
    assert len(attempts) == min(failures + 1, 20)
    assert sleeps == [0.025] * min(failures, 19)


def test_atomic_json_replace_does_not_retry_nonpermission_storage_failure(tmp_path, monkeypatch):
    path, attempts = tmp_path / 'status.json', []
    path.write_bytes(b'prior bytes')
    def fail(source, destination):
        attempts.append(source)
        raise OSError(errno.ENOSPC, SECRET)
    monkeypatch.setattr(Path, 'replace', fail)
    monkeypatch.setattr(pipeline.time, 'sleep', lambda *_: pytest.fail('Nonpermission failure must not retry'))
    with pytest.raises(OSError):
        pipeline.write_json(path, {'state': 'next'})
    assert len(attempts) == 1 and path.read_bytes() == b'prior bytes'


def test_os_attribute_getter_fault_cannot_mask_primary_error_classification():
    class HostileError(OSError):
        @property
        def winerror(self):
            raise RuntimeError(SECRET)
    state = publication.PublicationState()
    state.mark('convert_final', 'final.cdx.json')
    state.capture(HostileError(SECRET))
    assert state.details()['publication_os_error'] == 'other'
    assert state.details()['publication_error_code'] == 'PUBLICATION_IO_ERROR'
    assert SECRET not in json.dumps(state.details())


def test_nonstring_exception_class_name_is_normalized_without_membership_failure():
    class NameOverride(type):
        def __getattribute__(cls, name):
            return [] if name == '__name__' else super().__getattribute__(name)
    class HostileError(Exception, metaclass=NameOverride):
        pass
    assert publication.error_type_name(HostileError(SECRET)) == 'Exception'
    state = publication.PublicationState()
    state.capture(HostileError(SECRET))
    assert state.failure['error_type'] == 'Exception'


@pytest.mark.parametrize('mutation', ['mapping-subclass', 'key-subclass', 'value-subclass', 'unknown-key', 'path-value', 'nonbool-committed'])
def test_publication_details_only_allow_exact_types_and_fixed_internal_vocabulary(mutation):
    fields = {'publication_operation': 'convert_final', 'publication_error_code': 'PUBLICATION_FAILED',
              'publication_committed': False, 'publication_artifact': 'final.cdx.json'}
    original = copy.deepcopy(fields)
    class Derived(str):
        pass
    if mutation == 'mapping-subclass':
        fields = type('DerivedMapping', (dict,), {})(fields)
    elif mutation == 'key-subclass':
        fields = {Derived(key): value for key, value in fields.items()}
    elif mutation == 'value-subclass':
        fields['publication_operation'] = Derived('convert_final')
    elif mutation == 'unknown-key':
        fields[SECRET] = 'convert_final'
    elif mutation == 'path-value':
        fields['publication_artifact'] = SECRET + '/final.cdx.json'
    else:
        fields['publication_committed'] = 1
    assert publication.safe_details(fields) == {}
    assert publication.safe_details(original) == original

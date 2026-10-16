import hashlib
import json
import threading
import time
import uuid

import pytest
from fastapi import HTTPException

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import write_json
from sbom_creator.source_analysis import SourceAnalysisError
from sbom_creator.source_workflows import (
    SOURCE_ARTIFACTS,
    SourceWorkflows,
    _coordinate_agreement,
    _inventory,
)

REPOSITORY = 'https://git.example/team/project.git'
COMMIT = 'a' * 40
IMAGE = 'registry.example/team/project:pending'
IMMUTABLE = 'registry.example/team/project@sha256:' + 'b' * 64
CONFIG = 'sha256:' + 'c' * 64
SETTINGS = Settings(bitbucket_hosts=('git.example',), registry_hosts=('registry.example',),
                    source_image_wait_timeout=100, source_image_poll_interval=10,
                    source_image_probe_timeout=2)


def bom(purls=()):
    from packageurl import PackageURL
    components = []
    for index, value in enumerate(purls):
        package = PackageURL.from_string(value)
        component = {'type': 'library', 'name': package.name, 'version': package.version,
                     'purl': value, 'bom-ref': str(index)}
        if package.namespace:
            component['group'] = package.namespace
        components.append(component)
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'components': components, 'metadata': {'component': {
                'type': 'application', 'name': 'project', 'version': '1', 'bom-ref': 'root'}}}


def source_success(repository, commit, output, **kwargs):
    output.mkdir()
    write_json(output / 'source.cdx.json', bom(['pkg:maven/org.example/core@1',
                                              'pkg:npm/%40example/client@2']))
    digest = hashlib.sha256((output / 'source.cdx.json').read_bytes()).hexdigest()
    write_json(output / 'source-provenance.json', {'repository_url': repository,
        'commit': commit, 'source_sbom_sha256': digest, 'original_build_reproduced': False})
    write_json(output / 'source-summary.json', {'status': 'completed'})
    return {'status': 'completed', 'artifacts': list(SOURCE_ARTIFACTS)}


class Children:
    def __init__(self, root):
        self.root = root
        self.submissions = []
        self.states = {}

    def submit(self, reference):
        job_id = str(uuid.uuid4())
        self.submissions.append((job_id, reference))
        self.states[job_id] = {'id': job_id, 'status': 'queued'}
        return job_id

    def status(self, job_id):
        return self.states[job_id]

    def complete(self, *, purls=None, index=-1):
        job_id, reference = self.submissions[index]
        result = self.root / 'jobs' / job_id / 'result'
        result.mkdir(parents=True)
        write_json(result / 'full.cdx.json', bom(purls or ['pkg:maven/org.example/core@1',
                   'pkg:npm/%40example/client@3', 'pkg:deb/debian/base@1?arch=amd64']))
        write_json(result / 'provenance.json', {'request': {'image': reference},
            'image': {'image': reference, 'immutable_reference': reference,
                      'image_config_digest': CONFIG}})
        self.states[job_id]['status'] = 'succeeded'
        return result


@pytest.fixture
def workflow(tmp_path):
    created = []

    def make(*, source_runner=source_success, probe=lambda *args: {'status': 'waiting'},
             settings=SETTINGS, clock=None):
        children = Children(tmp_path)
        engine = SourceWorkflows(tmp_path, lambda: settings, children.submit, children.status,
                                 source_runner=source_runner, probe=probe)
        engine._check_loop = lambda: None
        if clock is not None:
            engine._clock = clock
        engine.start()
        created.append(engine)
        return engine, children

    yield make
    for engine in created:
        engine.stop()


def wait_source(engine, job_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = engine.status(job_id)
        if state['source_status'] in ('succeeded', 'failed'):
            return state
        time.sleep(0.005)
    raise AssertionError('Source worker did not complete')


def available(*args):
    return {'status': 'available', 'immutable_image': IMMUTABLE}


def test_source_only_is_downloadable_without_any_image_or_probe(workflow):
    def unexpected(*args):
        pytest.fail('No registry call was requested')

    engine, children = workflow(probe=unexpected)
    submitted = engine.submit(REPOSITORY, COMMIT)
    state = wait_source(engine, submitted['id'])
    engine._check()
    assert state['status'] == 'succeeded'
    assert state['image_status'] == 'not_requested'
    assert state['source_artifacts'] == list(SOURCE_ARTIFACTS)
    for name in SOURCE_ARTIFACTS:
        assert engine.artifact_path(state['id'], name).is_file()
    assert children.submissions == []
    with pytest.raises(HTTPException) as failure:
        engine.comparison_path(state['id'])
    assert failure.value.status_code == 409


def test_source_ready_while_image_waits_then_one_pinned_child_and_post_comparison(workflow):
    present = [False]
    calls = []
    now = [1000.0]

    def probe(*args):
        calls.append(args)
        return available() if present[0] else {'status': 'waiting'}

    engine, children = workflow(probe=probe, clock=lambda: now[0])
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    source_bytes = engine.artifact_path(job_id, 'source.cdx.json').read_bytes()
    engine._check()
    assert engine.status(job_id)['image_status'] == 'waiting'
    assert engine.artifact_path(job_id, 'source.cdx.json').read_bytes() == source_bytes
    engine._check()
    assert len(calls) == 1
    present[0] = True
    now[0] += 10
    engine._check()
    assert children.submissions[0][1] == IMMUTABLE
    assert engine.status(job_id)['source_status'] == 'succeeded'
    engine._check()
    assert len(children.submissions) == 1
    children.complete()
    engine._check()
    state = engine.status(job_id)
    assert state['status'] == state['comparison_status'] == 'succeeded'
    report = json.loads(engine.comparison_path(job_id).read_text())
    assert report['shared'] == ['pkg:maven/org.example/core@1']
    assert report['source_only'] == ['pkg:npm/%40example/client@2']
    assert report['image_only'] == ['pkg:npm/%40example/client@3']
    assert report['image_other_ecosystem_components'] == 1
    assert report['original_ci_graph_reproduced'] is False
    assert report['directness_inferred_from_presence'] is False
    assert report['binding']['image_config_digest'] == CONFIG
    assert report['binding']['image_job_id'] == children.submissions[0][0]
    assert not {'precision', 'recall', 'tp', 'fp', 'fn'} & report.keys()
    assert engine.artifact_path(job_id, 'source.cdx.json').read_bytes() == source_bytes


def test_image_can_finish_even_while_source_runner_is_blocked(workflow):
    entered, release = threading.Event(), threading.Event()

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return source_success(*args, **kwargs)

    engine, children = workflow(source_runner=blocked, probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    try:
        assert entered.wait(2)
        engine._check()
        children.complete()
        engine._check()
        assert engine.status(job_id)['image_status'] == 'succeeded'
        assert engine.status(job_id)['comparison_status'] == 'not_ready'
    finally:
        release.set()
    wait_source(engine, job_id)
    engine._check()
    assert engine.status(job_id)['comparison_status'] == 'succeeded'


def test_source_failure_preserves_independent_image_and_fixed_error(workflow):
    def failing(*args, **kwargs):
        raise SourceAnalysisError('source_cdxgen', 'RuntimeError', 'SOURCE_ENGINE_FAILED')

    engine, children = workflow(source_runner=failing, probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    children.complete()
    engine._check()
    state = engine.status(job_id)
    assert state['source_error']['code'] == 'SOURCE_ENGINE_FAILED'
    assert state['image_status'] == 'succeeded'
    assert state['comparison_status'] == 'skipped'
    assert state['comparison_error'] == 'SOURCE_UNAVAILABLE'
    assert state['status'] == 'partial'
    with pytest.raises(HTTPException) as failure:
        engine.artifact_path(job_id, 'source.cdx.json')
    assert failure.value.status_code == 409


def test_image_failure_does_not_remove_source_or_retry_child(workflow):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    children.states[children.submissions[0][0]].update(status='failed', error='secret-do-not-leak')
    engine._check()
    engine._check()
    state = engine.status(job_id)
    assert state['image_status'] == 'failed'
    assert state['image']['error'] == 'IMAGE_ANALYSIS_FAILED'
    assert state['status'] == 'partial'
    assert 'secret-do-not-leak' not in json.dumps(state)
    assert engine.artifact_path(job_id, 'source.cdx.json').exists()
    assert len(children.submissions) == 1


def test_waiting_is_bounded_and_probe_exception_is_redacted(workflow):
    calls, now = [], [1000.0]

    def probe(*args):
        calls.append(1)
        raise RuntimeError('registry-password-must-not-be-published')

    engine, children = workflow(probe=probe, clock=lambda: now[0])
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    now[0] += 1
    engine._check()
    assert len(calls) == 1
    now[0] += 99
    engine._check()
    state = engine.status(job_id)
    assert state['image']['error'] == 'IMAGE_WAIT_EXPIRED'
    assert 'registry-password' not in json.dumps(state)
    assert engine.artifact_path(job_id, 'source.cdx.json').is_file()
    assert children.submissions == []


@pytest.mark.parametrize('resolved', [
    'other.example/team/project@sha256:' + 'b' * 64,
    'registry.example/different/project@sha256:' + 'b' * 64,
    'registry.example/team/project:unbound',
    'https://name:password@registry.example/team/project@sha256:' + 'b' * 64,
    None])
def test_unbound_probe_output_never_becomes_child_input(workflow, resolved):
    engine, children = workflow(probe=lambda *args: {'status': 'available', 'immutable_image': resolved})
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    assert children.submissions == []
    state = engine.status(job_id)
    assert state['image_status'] == 'failed'
    assert 'password' not in json.dumps(state)


def test_exact_digest_request_cannot_change_at_probe(workflow):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT,
                           'registry.example/team/project@sha256:' + 'd' * 64)['id']
    wait_source(engine, job_id)
    engine._check()
    assert children.submissions == []
    assert engine.status(job_id)['image_status'] == 'failed'


def test_attach_rejects_busy_retry_preserves_previous_comparison_and_source(workflow):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT)['id']
    wait_source(engine, job_id)
    original = engine.artifact_path(job_id, 'source.cdx.json').read_bytes()
    engine.attach_image(job_id, IMAGE)
    with pytest.raises(HTTPException) as failure:
        engine.attach_image(job_id, IMAGE)
    assert failure.value.status_code == 409
    engine._check()
    children.complete()
    engine._check()
    old_path = engine.comparison_path(job_id)
    old_bytes = old_path.read_bytes()
    state = engine.attach_image(job_id, IMAGE)
    assert state['image']['attempt'] == 2
    assert state['image_attempts'][0]['comparison_status'] == 'succeeded'
    assert state['image_attempts'][0]['job_id'] == children.submissions[0][0]
    engine._check()
    children.complete()
    engine._check()
    assert engine.comparison_path(job_id) != old_path
    assert old_path.read_bytes() == old_bytes
    assert engine.artifact_path(job_id, 'source.cdx.json').read_bytes() == original


def test_attach_race_accepts_only_one_attempt(workflow):
    engine, _ = workflow()
    job_id = engine.submit(REPOSITORY, COMMIT)['id']
    wait_source(engine, job_id)
    barrier, outcomes = threading.Barrier(2), []

    def attach():
        barrier.wait()
        try:
            outcomes.append(engine.attach_image(job_id, IMAGE)['image_status'])
        except HTTPException as error:
            outcomes.append(error.status_code)

    threads = [threading.Thread(target=attach) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert sorted(outcomes, key=str) == [409, 'waiting']
    assert engine.status(job_id)['image']['attempt'] == 1


def test_probe_does_not_hold_status_lock_or_source_executor(workflow):
    entered, release = threading.Event(), threading.Event()

    def blocked(*args):
        entered.set()
        assert release.wait(5)
        return {'status': 'waiting'}

    engine, _ = workflow(probe=blocked)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    checker = threading.Thread(target=engine._check)
    checker.start()
    try:
        assert entered.wait(2)
        assert wait_source(engine, job_id)['source_status'] == 'succeeded'
        assert engine.artifact_path(job_id, 'source.cdx.json').exists()
    finally:
        release.set()
        checker.join(2)


def test_restart_keeps_source_and_original_wait_deadline_without_source_execution(workflow):
    now = [1000.0]
    engine, _ = workflow(clock=lambda: now[0])
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    original = wait_source(engine, job_id)
    source_bytes = engine.artifact_path(job_id, 'source.cdx.json').read_bytes()
    engine.stop()

    def never_run(*args, **kwargs):
        pytest.fail('Restart must not execute source again')

    resumed, children = workflow(source_runner=never_run, probe=available, clock=lambda: now[0])
    assert resumed.status(job_id)['image']['deadline_utc'] == original['image']['deadline_utc']
    resumed._check()
    assert children.submissions[0][1] == IMMUTABLE
    assert resumed.artifact_path(job_id, 'source.cdx.json').read_bytes() == source_bytes


def test_restart_marks_incomplete_source_failed_without_reexecution(workflow, tmp_path):
    engine, _ = workflow()
    job_id = engine.submit(REPOSITORY, COMMIT)['id']
    wait_source(engine, job_id)
    engine.stop()
    path = tmp_path / 'source-jobs' / job_id / 'status.json'
    state = json.loads(path.read_text())
    state['source_status'] = 'running'
    write_json(path, state)
    (path.parent / 'source/source-summary.json').unlink()
    resumed, _ = workflow(source_runner=lambda *args, **kwargs: pytest.fail('Reexecuted source'))
    assert resumed.status(job_id)['source_status'] == 'failed'
    assert resumed.status(job_id)['source_error']['code'] == 'SOURCE_INTERRUPTED'


def test_restart_recovers_complete_source_commit_without_reexecution(workflow, tmp_path):
    engine, _ = workflow()
    job_id = engine.submit(REPOSITORY, COMMIT)['id']
    wait_source(engine, job_id)
    original = engine.artifact_path(job_id, 'source.cdx.json').read_bytes()
    engine.stop()
    path = tmp_path / 'source-jobs' / job_id / 'status.json'
    state = json.loads(path.read_text())
    state['source_status'] = 'running'
    write_json(path, state)
    resumed, _ = workflow(source_runner=lambda *args, **kwargs: pytest.fail('Reexecuted source'))
    assert resumed.status(job_id)['source_status'] == 'succeeded'
    assert resumed.status(job_id)['source_recovered_after_restart'] is True
    assert resumed.artifact_path(job_id, 'source.cdx.json').read_bytes() == original


def test_restart_recovers_comparison_commit_without_overwriting_file(workflow, tmp_path):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    children.complete()
    engine._check()
    comparison = engine.comparison_path(job_id)
    original = comparison.read_bytes()
    engine.stop()
    path = tmp_path / 'source-jobs' / job_id / 'status.json'
    state = json.loads(path.read_text())
    state['comparison_status'] = 'running'
    write_json(path, state)
    resumed, _ = workflow(source_runner=lambda *args, **kwargs: pytest.fail('Reexecuted source'))
    resumed._check()
    assert resumed.status(job_id)['comparison_status'] == 'succeeded'
    assert resumed.comparison_path(job_id).read_bytes() == original


def test_index_digest_comparison_requires_scanner_binding_to_platform_manifest(workflow):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    result = children.complete()
    path = result / 'provenance.json'
    data = json.loads(path.read_text())
    platform = 'registry.example/team/project@sha256:' + 'e' * 64
    data['image'].update(immutable_reference=platform, repo_digests=[IMMUTABLE])
    write_json(path, data)
    engine._check()
    report = json.loads(engine.comparison_path(job_id).read_text())
    assert report['binding']['immutable_image'] == IMMUTABLE
    assert report['binding']['resolved_platform_image'] == platform


def test_unbound_different_platform_manifest_fails_comparison(workflow):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    result = children.complete()
    path = result / 'provenance.json'
    data = json.loads(path.read_text())
    data['image']['immutable_reference'] = 'registry.example/team/project@sha256:' + 'e' * 64
    write_json(path, data)
    engine._check()
    assert engine.status(job_id)['comparison_status'] == 'failed'


def test_checker_boundary_survives_and_never_logs_raw_error(workflow, caplog):
    engine, _ = workflow()
    calls = []

    def failed_check():
        calls.append(1)
        engine._stop.set()
        raise RuntimeError('private-registry-credentials')

    engine._check = failed_check
    SourceWorkflows._check_loop(engine)
    assert calls == [1]
    assert 'source_workflow.check_failed' in caplog.text
    assert 'private-registry-credentials' not in caplog.text


@pytest.mark.parametrize('tamper', ['source_commit', 'source_hash', 'image_reference', 'image_schema'])
def test_comparison_rejects_wrong_binding_or_schema_without_losing_either_result(workflow, tamper):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    result = children.complete()
    if tamper.startswith('source'):
        path = engine.artifact_path(job_id, 'source-provenance.json')
        data = json.loads(path.read_text())
        data['commit' if tamper == 'source_commit' else 'source_sbom_sha256'] = 'd' * 40
    elif tamper == 'image_reference':
        path = result / 'provenance.json'
        data = json.loads(path.read_text())
        data['image']['immutable_reference'] = 'registry.example/other@sha256:' + 'b' * 64
    else:
        path = result / 'full.cdx.json'
        data = {'secret': 'do-not-serialize'}
    write_json(path, data)
    engine._check()
    state = engine.status(job_id)
    assert state['source_status'] == state['image_status'] == 'succeeded'
    assert state['comparison_status'] == 'failed'
    assert state['comparison_error'] == 'COMPARISON_FAILED'
    assert state['status'] == 'partial'
    assert engine.artifact_path(job_id, 'source.cdx.json').exists()
    assert (result / 'full.cdx.json').exists()
    assert 'do-not-serialize' not in json.dumps(state)


def test_exact_purl_qualifiers_subpath_and_platform_scope_are_preserved():
    values = ['pkg:npm/%40example/client@1?arch=amd64',
              'pkg:npm/%40example/client@1?arch=arm64',
              'pkg:maven/org.example/core@2?type=jar#lib',
              'pkg:maven/org.example/core@2?type=jar#other',
              'pkg:deb/debian/base@1?arch=amd64']
    identities, other, unknown = _inventory(bom(values))
    assert identities == set(values[:-1])
    assert other == 1 and unknown == 0


def test_coordinate_view_explains_jar_qualifier_without_changing_exact_comparison(workflow):
    def qualified_source(*args, **kwargs):
        source_success(*args, **kwargs)
        output = args[2]
        write_json(output / 'source.cdx.json', bom(['pkg:maven/org.example/core@1?type=jar']))
        path = output / 'source-provenance.json'
        provenance = json.loads(path.read_text())
        provenance['source_sbom_sha256'] = hashlib.sha256((output / 'source.cdx.json').read_bytes()).hexdigest()
        write_json(path, provenance)

    engine, children = workflow(probe=available, source_runner=qualified_source)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    children.complete(purls=['pkg:maven/org.example/core@1'])
    engine._check()
    comparison = json.loads(engine.comparison_path(job_id).read_text())
    assert comparison['shared'] == []
    assert comparison['source_only'] == ['pkg:maven/org.example/core@1?type=jar']
    assert comparison['image_only'] == ['pkg:maven/org.example/core@1']
    coordinates = comparison['coordinate_agreement']
    assert coordinates['claim'] == 'coordinate_agreement_not_full_package_identity'
    assert coordinates['shared'] == ['pkg:maven/org.example/core@1']
    assert coordinates['source_only'] == coordinates['image_only'] == []
    assert coordinates['shared_variant_details'] == [{
        'coordinate': 'pkg:maven/org.example/core@1',
        'source_purls': ['pkg:maven/org.example/core@1?type=jar'],
        'image_purls': ['pkg:maven/org.example/core@1'],
        'exact_shared_purls': [], 'variant_sets_differ': True}]
    assert not {'precision', 'recall', 'tp', 'fp', 'fn'} & coordinates.keys()


def test_coordinate_view_retains_scoped_npm_subpath_variants_and_exact_shared_identity():
    source = {'pkg:npm/%40example/client@1#lib', 'pkg:npm/%40example/client@1#shared'}
    image = {'pkg:npm/%40example/client@1#dist', 'pkg:npm/%40example/client@1#shared'}
    report = _coordinate_agreement(source, image)
    assert report['shared'] == ['pkg:npm/%40example/client@1']
    details = report['shared_variant_details'][0]
    assert details['source_purls'] == sorted(source)
    assert details['image_purls'] == sorted(image)
    assert details['exact_shared_purls'] == ['pkg:npm/%40example/client@1#shared']
    assert details['variant_sets_differ'] is True
    assert source & image == {'pkg:npm/%40example/client@1#shared'}


def test_coordinate_view_never_merges_version_namespace_ecosystem_or_aliases():
    source = {'pkg:maven/org.example/core@1?type=jar', 'pkg:maven/org.example/core@2',
              'pkg:npm/%40example/client@1', 'pkg:maven/org.old/core@1'}
    image = {'pkg:maven/org.example/core@1', 'pkg:maven/org.example/core@3',
             'pkg:npm/%40different/client@1', 'pkg:maven/org.new/core@1'}
    report = _coordinate_agreement(source, image)
    assert report['shared'] == ['pkg:maven/org.example/core@1']
    assert report['source_only'] == ['pkg:maven/org.example/core@2',
                                     'pkg:maven/org.old/core@1', 'pkg:npm/%40example/client@1']
    assert report['image_only'] == ['pkg:maven/org.example/core@3',
                                    'pkg:maven/org.new/core@1', 'pkg:npm/%40different/client@1']


def test_source_queue_capacity_rejects_without_running_more_than_one(workflow):
    entered, release = threading.Event(), threading.Event()

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return source_success(*args, **kwargs)

    engine, _ = workflow(source_runner=blocked)
    try:
        jobs = [engine.submit(REPOSITORY, COMMIT) for _ in range(16)]
        assert entered.wait(2)
        assert sum(engine.status(job['id'])['source_status'] == 'running' for job in jobs) == 1
        with pytest.raises(HTTPException) as failure:
            engine.submit(REPOSITORY, COMMIT)
        assert failure.value.status_code == 429
    finally:
        release.set()


@pytest.mark.parametrize('job_id', ['../jobs', '..', 'NOT-A-UUID', 'A' * 40])
def test_unknown_ids_and_traversal_are_fixed_404(workflow, job_id):
    engine, _ = workflow()
    with pytest.raises(HTTPException) as failure:
        engine.status(job_id)
    assert failure.value.status_code == 404


@pytest.mark.parametrize('name', ['../status.json', 'status.json', '/secrets', 'comparison.json'])
def test_source_artifacts_never_expose_state_or_arbitrary_paths(workflow, name):
    engine, _ = workflow()
    job_id = engine.submit(REPOSITORY, COMMIT)['id']
    wait_source(engine, job_id)
    with pytest.raises(HTTPException) as failure:
        engine.artifact_path(job_id, name)
    assert failure.value.status_code == 404


def test_untyped_source_failure_cannot_forge_error_fields_or_leak_secret(workflow):
    class SecretFailure(RuntimeError):
        @property
        def code(self):
            pytest.fail('Untrusted error properties must not be evaluated')

    def failing(*args, **kwargs):
        raise SecretFailure('my-password-and-local-path')

    engine, _ = workflow(source_runner=failing)
    job_id = engine.submit(REPOSITORY, COMMIT)['id']
    state = wait_source(engine, job_id)
    assert state['source_error']['code'] == 'SOURCE_ANALYSIS_FAILED'
    assert 'my-password' not in json.dumps(state)


def test_retry_after_image_failure_uses_new_attempt_directory(workflow):
    engine, children = workflow(probe=available)
    job_id = engine.submit(REPOSITORY, COMMIT, IMAGE)['id']
    wait_source(engine, job_id)
    engine._check()
    children.states[children.submissions[0][0]]['status'] = 'failed'
    engine._check()
    state = engine.attach_image(job_id, IMAGE)
    assert state['image']['attempt'] == 2
    assert state['image_attempts'][0]['status'] == 'failed'
    assert state['image_attempts'][0]['error'] == 'IMAGE_ANALYSIS_FAILED'


def test_foreign_inputs_rejected_before_any_work(workflow):
    engine, children = workflow()
    for repository, commit, image in [('https://evil.example/a', COMMIT, None),
                                       (REPOSITORY, 'main', None),
                                       (REPOSITORY, COMMIT, 'evil.example/project:1')]:
        with pytest.raises(HTTPException) as failure:
            engine.submit(repository, commit, image)
        assert failure.value.status_code == 422
    assert children.submissions == []
    assert list(engine.jobs.iterdir()) == []

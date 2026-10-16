"""Independent source publication, bounded image waiting and post-job comparison.

Source output is immutable and downloadable independently from image availability.
The checker never owns an image worker while waiting for a registry manifest.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import stat
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from fastapi import HTTPException
from packageurl import PackageURL

from .acquire import image_reference, validate_commit, validate_repository_url
from .pipeline import write_json
from .publication import ERROR_TYPES, error_type_name
from .validation import validate_cyclonedx

SOURCE_ARTIFACTS = ('source.cdx.json', 'source-provenance.json', 'source-summary.json')
SOURCE_STAGES = frozenset({'source_checkout', 'source_cdxgen', 'source_validation',
                           'source_publication'})
SOURCE_CODES = frozenset({'SOURCE_CHECKOUT_FAILED', 'SOURCE_UNSUPPORTED', 'SOURCE_ENGINE_FAILED',
    'SOURCE_INVALID_RESULT', 'SOURCE_PUBLICATION_FAILED', 'SOURCE_ANALYSIS_FAILED'})
ACTIVE_SOURCE = frozenset({'queued', 'running'})
ACTIVE_IMAGE = frozenset({'waiting', 'running'})
SHA256 = re.compile(r'^sha256:[a-f0-9]{64}$')


def _source_runner(*args, **kwargs):
    from .source_analysis import analyze_source
    return analyze_source(*args, **kwargs)


def _probe(*args, **kwargs):
    from .image_probe import probe
    return probe(*args, **kwargs)


def _utc(timestamp):
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


def _timestamp(value):
    return datetime.fromisoformat(value).timestamp()


def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise HTTPException(404, 'Source analysis not found') from None
    return value


def _regular(path, root):
    """Only owned regular files, with no symlink/reparse traversal, are exposed."""
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Unsupported linked result')
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Result is not a regular file')
    return path


def _document(path, root, limit):
    _regular(path, root)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Result exceeds configured limit')
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def _repository(reference):
    base = reference.split('@', 1)[0]
    head, _, tail = base.rpartition('/')
    return head + '/' + tail.split(':', 1)[0]


def _bound_reference(requested, resolved, settings):
    if type(resolved) is not str:
        raise ValueError('Missing immutable reference')
    resolved = image_reference(resolved, settings)
    if '@' not in resolved or not SHA256.fullmatch(resolved.rsplit('@', 1)[1]):
        raise ValueError('Probe did not resolve an immutable reference')
    if _repository(requested) != _repository(resolved):
        raise ValueError('Probe changed repository')
    if '@' in requested and requested.rsplit('@', 1)[1] != resolved.rsplit('@', 1)[1]:
        raise ValueError('Probe changed requested digest')
    return resolved


def _inventory(document):
    """Full exact Maven/npm PURLs; qualifiers and subpaths are not discarded."""
    identities, unsupported, unknown = set(), 0, 0
    root = document.get('metadata', {}).get('component', {})
    pending = list(document.get('components', [])) + list(root.get('components', []))
    root_ref = root.get('bom-ref')
    while pending:
        component = pending.pop()
        pending.extend(component.get('components', []))
        if root_ref and component.get('bom-ref') == root_ref:
            continue
        try:
            parsed = PackageURL.from_string(component.get('purl', ''))
            if parsed.type not in ('maven', 'npm'):
                unsupported += 1
                continue
            if not parsed.version or component.get('version') != parsed.version:
                raise ValueError('Version is not established')
            identities.add(parsed.to_string())
        except (ValueError, TypeError, AttributeError):
            unknown += 1
    return identities, unsupported, unknown


def _coordinate_agreement(source_purls, image_purls):
    """A secondary coordinate view; exact variant identities remain separate."""
    def index(values):
        result = {}
        for value in values:
            parsed = PackageURL.from_string(value)
            coordinate = parsed._replace(qualifiers={}, subpath=None).to_string()
            result.setdefault(coordinate, set()).add(value)
        return result

    source, image = index(source_purls), index(image_purls)
    shared = sorted(source.keys() & image.keys())
    return {'unit': 'ecosystem_namespace_name_exact_version_without_qualifiers_or_subpath',
            'claim': 'coordinate_agreement_not_full_package_identity',
            'shared': shared,
            'source_only': sorted(source.keys() - image.keys()),
            'image_only': sorted(image.keys() - source.keys()),
            'shared_variant_details': [
                {'coordinate': coordinate, 'source_purls': sorted(source[coordinate]),
                 'image_purls': sorted(image[coordinate]),
                 'exact_shared_purls': sorted(source[coordinate] & image[coordinate]),
                 'variant_sets_differ': source[coordinate] != image[coordinate]}
                for coordinate in shared]}


class SourceWorkflows:
    """One source executor and one bounded registry/status checker per service."""

    def __init__(self, root, settings_provider, submit_image, image_status,
                 source_runner=None, probe=None):
        self.root = Path(root).resolve()
        self.jobs = self.root / 'source-jobs'
        self.settings_provider = settings_provider
        self.submit_image = submit_image
        self.image_status = image_status
        self.source_runner = source_runner or _source_runner
        self.probe = probe or _probe
        self._lock = threading.RLock()
        self._capacity = threading.BoundedSemaphore(16)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='source-sbom')
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._started = False
        self._inflight = set()
        self._clock = time.time

    def _directory(self, job_id):
        directory = self.jobs / _uuid(job_id)
        try:
            _regular(directory / 'status.json', self.root)
        except (OSError, ValueError):
            raise HTTPException(404, 'Source analysis not found') from None
        return directory

    def _read(self, directory):
        document, _ = _document(directory / 'status.json', self.root, 1024 * 1024)
        return document

    def _save(self, directory, state):
        source, image = state['source_status'], state['image_status']
        if (source in ACTIVE_SOURCE or image in ACTIVE_IMAGE
                or state['comparison_status'] == 'running'
                or image == 'succeeded' and state['comparison_status'] == 'not_ready'):
            state['status'] = 'running'
        elif state['comparison_status'] == 'failed':
            state['status'] = 'partial'
        elif source == 'succeeded' and image in ('succeeded', 'not_requested'):
            state['status'] = 'succeeded'
        elif source == 'succeeded' or image == 'succeeded':
            state['status'] = 'partial'
        else:
            state['status'] = 'failed'
        write_json(directory / 'status.json', state)

    def start(self):
        with self._lock:
            if self._started:
                return
            self.jobs.mkdir(parents=True, exist_ok=True)
            for directory in self.jobs.iterdir():
                try:
                    _uuid(directory.name)
                    state = self._read(directory)
                    if state['source_status'] in ACTIVE_SOURCE:
                        try:
                            self._source_binding(directory, state)
                            state.update(source_status='succeeded',
                                         source_artifacts=list(SOURCE_ARTIFACTS),
                                         source_recovered_after_restart=True)
                        except Exception:  # noqa: BLE001 -- incomplete source output is never reexecuted
                            state.update(source_status='failed', source_error={
                                'stage': 'source_publication', 'code': 'SOURCE_INTERRUPTED',
                                'error_type': 'RuntimeError'})
                    if state['comparison_status'] == 'running':
                        state['comparison_status'] = 'not_ready'
                    self._save(directory, state)
                except (HTTPException, OSError, ValueError, KeyError, TypeError):
                    # A foreign/corrupt directory is neither executed nor rewritten.
                    continue
            self._started = True
            self._thread = threading.Thread(target=self._check_loop, name='source-image-wait',
                                            daemon=True)
            self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join()
        self._executor.shutdown(wait=True, cancel_futures=False)

    def submit(self, repository_url, commit, image=None):
        configured = self.settings_provider()
        try:
            repository_url = validate_repository_url(repository_url, configured)
            commit = validate_commit(commit)
            image = image_reference(image, configured) if image is not None else None
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid or unauthorized repository/commit/image') from None
        with self._lock:
            if not self._started or self._stop.is_set():
                raise HTTPException(503, 'Source analyses are unavailable')
            if not self._capacity.acquire(blocking=False):
                raise HTTPException(429, 'Source job queue is full')
            job_id = str(uuid.uuid4())
            directory = self.jobs / job_id
            state = {'id': job_id, 'status_url': f'/v1/source-analyses/{job_id}',
                     'repository_url': repository_url, 'commit': commit,
                     'source_status': 'queued', 'source_artifacts': [],
                     'image_status': 'not_requested', 'image': None, 'image_attempts': [],
                     'comparison_status': 'not_ready'}
            try:
                directory.mkdir()
                if image is not None:
                    self._new_attempt(directory, state, image, configured)
                self._save(directory, state)
                self._executor.submit(self._execute_source, directory, repository_url, commit,
                                      configured)
            except Exception:
                self._capacity.release()
                raise
        self._wake.set()
        return copy.deepcopy(state)

    def status(self, job_id):
        with self._lock:
            try:
                return self._read(self._directory(job_id))
            except (OSError, ValueError, KeyError):
                raise HTTPException(503, 'Source analysis state is unavailable') from None

    def _new_attempt(self, directory, state, image, configured):
        if state['image'] is not None:
            previous = copy.deepcopy(state['image'])
            previous.update(status=state['image_status'], comparison_status=state['comparison_status'])
            state['image_attempts'].append(previous)
        number = len(state['image_attempts']) + 1
        (directory / 'attempts' / f'{number:04d}').mkdir(parents=True)
        now = self._clock()
        state['image'] = {'attempt': number, 'requested_image': image,
                          'deadline_utc': _utc(now + configured.source_image_wait_timeout),
                          'next_probe_utc': _utc(now)}
        state.update(image_status='waiting', comparison_status='not_ready')
        state.pop('comparison_error', None)

    def attach_image(self, job_id, image):
        configured = self.settings_provider()
        try:
            image = image_reference(image, configured)
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid or unauthorized image') from None
        with self._lock:
            directory = self._directory(job_id)
            state = self._read(directory)
            if (state['image_status'] in ACTIVE_IMAGE
                    or state['comparison_status'] in ('running', 'not_ready')
                    and state['image_status'] == 'succeeded'):
                raise HTTPException(409, 'An image attempt is already active')
            self._new_attempt(directory, state, image, configured)
            self._save(directory, state)
        self._wake.set()
        return state

    def artifact_path(self, job_id, name):
        if name not in SOURCE_ARTIFACTS:
            raise HTTPException(404, 'Source artifact not found')
        with self._lock:
            directory = self._directory(job_id)
            if self._read(directory)['source_status'] != 'succeeded':
                raise HTTPException(409, 'Source results are not published')
            path = directory / 'source' / name
            try:
                return _regular(path, self.root)
            except (OSError, ValueError):
                raise HTTPException(404, 'Source artifact not found') from None

    def comparison_path(self, job_id):
        with self._lock:
            directory = self._directory(job_id)
            state = self._read(directory)
            if state['comparison_status'] != 'succeeded':
                raise HTTPException(409, 'Comparison is not available')
            path = directory / 'attempts' / f"{state['image']['attempt']:04d}" / 'comparison.json'
            try:
                return _regular(path, self.root)
            except (OSError, ValueError):
                raise HTTPException(404, 'Comparison not found') from None

    def _execute_source(self, directory, repository_url, commit, configured):
        try:
            with self._lock:
                state = self._read(directory)
                state['source_status'] = 'running'
                self._save(directory, state)
            self.source_runner(repository_url, commit, directory / 'source', settings=configured)
            self._source_binding(directory, {'repository_url': repository_url, 'commit': commit})
            with self._lock:
                state = self._read(directory)
                state.update(source_status='succeeded', source_artifacts=list(SOURCE_ARTIFACTS))
                self._save(directory, state)
        except Exception as error:  # noqa: BLE001 -- independent source job failure boundary
            details = {'stage': 'source_publication', 'code': 'SOURCE_ANALYSIS_FAILED',
                       'error_type': error_type_name(error)}
            # Only the internally defined typed boundary can supply fixed source details.
            from .source_analysis import SourceAnalysisError
            if type(error) is SourceAnalysisError:
                if error.stage in SOURCE_STAGES:
                    details['stage'] = error.stage
                if error.code in SOURCE_CODES:
                    details['code'] = error.code
                if type(error.error_type) is str and error.error_type in ERROR_TYPES:
                    details['error_type'] = error.error_type
            with self._lock:
                state = self._read(directory)
                state.update(source_status='failed', source_error=details)
                self._save(directory, state)
        finally:
            self._capacity.release()
            self._wake.set()

    def _check_loop(self):
        while not self._stop.is_set():
            self._wake.clear()
            try:
                self._check()
            except Exception:  # noqa: BLE001 -- a single checker failure must not stop future checks
                logging.getLogger('uvicorn.error').warning('source_workflow.check_failed')
            self._wake.wait(0.5)

    def _check(self):
        for directory in self.jobs.iterdir():
            if self._stop.is_set():
                break
            try:
                with self._lock:
                    _uuid(directory.name)
                    state = self._read(directory)
                    if directory.name in self._inflight:
                        continue
                    self._inflight.add(directory.name)
                try:
                    if state['image_status'] == 'waiting':
                        self._probe_image(directory, state)
                    elif state['image_status'] == 'running':
                        self._poll_image(directory, state)
                    with self._lock:
                        state = self._read(directory)
                    if state['image_status'] == 'succeeded':
                        self._maybe_compare(directory, state)
                finally:
                    with self._lock:
                        self._inflight.discard(directory.name)
            except (OSError, ValueError, KeyError, TypeError, HTTPException):
                # Corrupt owned state is not executable input; other jobs continue.
                continue

    def _image_failure(self, directory, state, code):
        state.update(image_status='failed', comparison_status='skipped')
        state['image']['error'] = code
        self._save(directory, state)

    def _probe_image(self, directory, snapshot):
        attempt = snapshot['image']['attempt']
        now = self._clock()
        if now >= _timestamp(snapshot['image']['deadline_utc']):
            with self._lock:
                state = self._read(directory)
                if state['image']['attempt'] == attempt:
                    self._image_failure(directory, state, 'IMAGE_WAIT_EXPIRED')
            return
        if now < _timestamp(snapshot['image']['next_probe_utc']):
            return
        configured = self.settings_provider()
        try:
            result = self.probe(snapshot['image']['requested_image'], configured)
            if type(result) is not dict or result.get('status') not in ('available', 'waiting', 'failed'):
                raise ValueError('Invalid probe result')
            immutable = None
            if result['status'] == 'available':
                try:
                    immutable = _bound_reference(snapshot['image']['requested_image'],
                                                 result.get('immutable_image'), configured)
                except ValueError:
                    result = {'status': 'failed'}
        except Exception:  # noqa: BLE001 -- no external probe message crosses the API
            result, immutable = {'status': 'waiting'}, None
        with self._lock:
            state = self._read(directory)
            if state['image']['attempt'] != attempt or state['image_status'] != 'waiting':
                return
            state['image']['next_probe_utc'] = _utc(self._clock() + configured.source_image_poll_interval)
            if self._clock() >= _timestamp(state['image']['deadline_utc']):
                self._image_failure(directory, state, 'IMAGE_WAIT_EXPIRED')
                return
            if result['status'] == 'failed':
                self._image_failure(directory, state, 'IMAGE_PROBE_REJECTED')
                return
            if immutable is None:
                state['image']['last_probe'] = 'unavailable_or_unconfirmed'
                self._save(directory, state)
                return
            # Persist the claim before invoking the child service outside our lock.
            state['image'].update(immutable_image=immutable, submission_started=True)
            state['image_status'] = 'running'
            self._save(directory, state)
        try:
            child_id = _uuid(self.submit_image(immutable))
        except Exception as error:  # noqa: BLE001 -- child submission failure preserves source
            with self._lock:
                state = self._read(directory)
                if type(error) is HTTPException and error.status_code == 429:
                    state['image_status'] = 'waiting'
                    self._save(directory, state)
                else:
                    self._image_failure(directory, state, 'IMAGE_SUBMISSION_FAILED')
            return
        with self._lock:
            state = self._read(directory)
            state['image'].update(job_id=child_id, status_url=f'/v1/analyses/{child_id}')
            self._save(directory, state)

    def _poll_image(self, directory, snapshot):
        child_id = snapshot['image'].get('job_id')
        if not child_id:
            with self._lock:
                self._image_failure(directory, self._read(directory), 'IMAGE_SUBMISSION_INTERRUPTED')
            return
        try:
            child = self.image_status(child_id)
            status = child.get('status')
        except Exception:  # noqa: BLE001 -- child API diagnostics remain in the child job
            status = 'failed'
        if status in ('queued', 'running'):
            return
        with self._lock:
            state = self._read(directory)
            if status == 'succeeded':
                state['image_status'] = 'succeeded'
                self._save(directory, state)
            else:
                self._image_failure(directory, state, 'IMAGE_ANALYSIS_FAILED')

    def _maybe_compare(self, directory, snapshot):
        if snapshot['comparison_status'] != 'not_ready':
            return
        if snapshot['source_status'] in ACTIVE_SOURCE:
            return
        if snapshot['source_status'] != 'succeeded':
            with self._lock:
                state = self._read(directory)
                state.update(comparison_status='skipped', comparison_error='SOURCE_UNAVAILABLE')
                self._save(directory, state)
            return
        with self._lock:
            state = self._read(directory)
            state['comparison_status'] = 'running'
            self._save(directory, state)
        try:
            comparison = self._compare(directory, snapshot)
            target = directory / 'attempts' / f"{snapshot['image']['attempt']:04d}" / 'comparison.json'
            if target.exists():
                # A process may stop after atomic file publication but before the
                # status transition. Recompute bindings and compare without replacing it.
                previous, _ = _document(target, self.root, self.settings_provider().max_sbom_bytes)
                if previous != comparison:
                    raise FileExistsError('A different comparison is already published')
            else:
                write_json(target, comparison)
            with self._lock:
                state = self._read(directory)
                state['comparison_status'] = 'succeeded'
                self._save(directory, state)
        except Exception:  # noqa: BLE001 -- source and image artifacts remain downloadable
            with self._lock:
                state = self._read(directory)
                state.update(comparison_status='failed', comparison_error='COMPARISON_FAILED')
                self._save(directory, state)

    def _compare(self, directory, state):
        limit = self.settings_provider().max_sbom_bytes
        source, source_sha, source_provenance_sha = self._source_binding(directory, state)
        child_id = _uuid(state['image']['job_id'])
        image_result = self.root / 'jobs' / child_id / 'result'
        image, image_sha = _document(image_result / 'full.cdx.json', self.root, limit)
        image_provenance, image_provenance_sha = _document(
            image_result / 'provenance.json', self.root, limit)
        validate_cyclonedx(image, versions=('1.6', '1.7'))
        immutable = state['image']['immutable_image']
        image_binding = image_provenance.get('image', {})
        platform_image = image_reference(image_binding.get('immutable_reference'), self.settings_provider())
        if ('@' not in platform_image or _repository(platform_image) != _repository(immutable)
                or not SHA256.fullmatch(platform_image.rsplit('@', 1)[1])):
            raise ValueError('Image platform binding is not immutable')
        if (image_provenance.get('request', {}).get('image') != immutable
                or image_binding.get('image') != immutable
                or platform_image != immutable and immutable not in image_binding.get('repo_digests', [])
                or not SHA256.fullmatch(image_binding.get('image_config_digest', ''))):
            raise ValueError('Image provenance does not bind this result')
        source_set, source_other, source_unknown = _inventory(source)
        image_set, image_other, image_unknown = _inventory(image)
        return {'status': 'completed', 'kind': 'source_image_inventory_agreement',
                'unit': 'unique_exact_maven_npm_purl_with_qualifiers_and_subpath',
                'source_scope': 'available_source_model_resolution_environment',
                'image_scope': 'full_delivered_inventory_including_platform_components',
                'original_ci_graph_reproduced': False, 'reference_used_as_input': False,
                'directness_inferred_from_presence': False,
                'binding': {'source_analysis_id': state['id'], 'commit': state['commit'],
                            'repository_url': state['repository_url'],
                            'source_sbom_sha256': source_sha,
                            'source_provenance_sha256': source_provenance_sha,
                            'image_job_id': child_id, 'immutable_image': immutable,
                            'resolved_platform_image': platform_image,
                            'image_config_digest': image_binding['image_config_digest'],
                            'image_sbom_sha256': image_sha,
                            'image_provenance_sha256': image_provenance_sha},
                'source_count': len(source_set), 'image_count': len(image_set),
                'shared': sorted(source_set & image_set),
                'source_only': sorted(source_set - image_set),
                'image_only': sorted(image_set - source_set),
                'coordinate_agreement': _coordinate_agreement(source_set, image_set),
                'source_unresolved_components': source_unknown,
                'image_unresolved_components': image_unknown,
                'source_other_ecosystem_components': source_other,
                'image_other_ecosystem_components': image_other}

    def _source_binding(self, directory, state):
        limit = self.settings_provider().max_sbom_bytes
        source, source_sha = _document(directory / 'source/source.cdx.json', self.root, limit)
        provenance, provenance_sha = _document(
            directory / 'source/source-provenance.json', self.root, limit)
        summary, _ = _document(directory / 'source/source-summary.json', self.root, limit)
        validate_cyclonedx(source, versions=('1.6', '1.7'))
        if (provenance.get('commit') != state['commit']
                or provenance.get('repository_url') != state['repository_url']
                or provenance.get('source_sbom_sha256') != source_sha
                or summary.get('status') != 'completed'):
            raise ValueError('Source provenance does not bind this result')
        return source, source_sha, provenance_sha

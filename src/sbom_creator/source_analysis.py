"""Independent source-model SBOM generation in an isolated, pinned cdxgen job.

The result describes the available resolution environment, never an attestation
of an unknown CI build or the contents of a future image.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path

from .acquire import (
    checkout,
    clean_environment,
    run_command,
    validate_commit,
    validate_repository_url,
)
from .build_backend import VERSION, source_archive
from .java_resolver import MIRRORS
from .publication import commit_directory, error_type_name
from .validation import validate_cyclonedx

ARTIFACTS = ('source.cdx.json', 'source-provenance.json', 'source-summary.json')
SCOPE = ('source model resolution in the available isolated build environment; '
         'original CI configuration unknown')
STAGES = frozenset({'source_checkout', 'source_cdxgen', 'source_validation', 'source_publication'})
CODES = frozenset({'SOURCE_CHECKOUT_FAILED', 'SOURCE_UNSUPPORTED', 'SOURCE_ENGINE_FAILED',
                   'SOURCE_INVALID_RESULT', 'SOURCE_PUBLICATION_FAILED'})
# Checkout is the exact repository revision, not an installed workspace. A
# tracked directory named "build" or "target" can be a real source module.
IGNORED_DIRECTORIES = frozenset({'.git'})


class SourceAnalysisError(RuntimeError):
    """Only fixed facts cross the source-job API boundary, never engine logs."""

    def __init__(self, stage, error_type, code):
        self.stage = stage if stage in STAGES else 'source_cdxgen'
        self.error_type = error_type if error_type in {
            'PermissionError', 'FileExistsError', 'FileNotFoundError', 'OSError', 'RuntimeError',
            'ValueError', 'TypeError', 'ValidationError', 'TimeoutError', 'JSONDecodeError',
            'RecursionError', 'MemoryError', 'Exception'} else 'Exception'
        self.code = code if code in CODES else 'SOURCE_ENGINE_FAILED'
        super().__init__(f'{self.stage}: {self.code}')


def _project_types(root):
    result = set()
    for count, (directory, names, files) in enumerate(os.walk(root, followlinks=False)):
        if count >= 10_000:
            raise ValueError('Source traversal budget')
        names[:] = sorted(name for name in names if name not in IGNORED_DIRECTORIES
                          and not (Path(directory) / name).is_symlink())
        if {'pom.xml', 'build.gradle', 'build.gradle.kts'} & set(files):
            result.add('java')
        if 'package.json' in files:
            result.add('js')
    return sorted(result)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _engine(checkout_path, settings, project_types):
    if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}', settings.cdxgen_image)
            or settings.java_maven_repository not in MIRRORS):
        raise ValueError('Invalid configured build engine image/repository')
    source = source_archive(checkout_path, excluded_directories=IGNORED_DIRECTORIES)
    environment = clean_environment()
    # These values select the coordinator connection; none is supplied using -e
    # or a mount to the untrusted project container.
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        if key in os.environ:
            environment[key] = os.environ[key]
    name = 'sbom-source-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='sbom-source-client-') as temporary:
        work = Path(temporary)
        image_id = run_command([settings.docker_binary, 'image', 'inspect', settings.cdxgen_image,
            '--format', '{{.Id}}'], cwd=work, env=environment, timeout=30,
            max_output_bytes=4096, label='Source engine identity').strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
            raise ValueError('Immutable source engine image required')
        types = ' '.join('-t ' + kind for kind in project_types)
        script = ('set -e; mkdir -p /tmp/project /tmp/home/.m2; '
            'tar --no-same-owner -xf - -C /tmp/project; '
            "printf '%s' '<settings><localRepository>/tmp/home/.m2/repository</localRepository>"
            '<mirrors><mirror><id>service</id><mirrorOf>*</mirrorOf><url>'
            + settings.java_maven_repository
            + "</url></mirror></mirrors></settings>' > /tmp/home/.m2/settings.xml; "
            'cd /tmp/project; cdxgen ' + types + ' --recurse --install-deps --spec-version 1.6 '
            '--fail-on-error -o /tmp/result.json . >/tmp/engine.log 2>&1; cat /tmp/result.json')
        args = [settings.docker_binary, 'run', '--rm', '--pull=never', '--name', name, '-i',
            '--read-only', '--user=65532:65532', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=3g', '--cpus=2', '--pids-limit=256', '--tmpfs', '/tmp:rw,size=2147483648',
            '-e', 'HOME=/tmp/home', '-e', 'PREFER_MAVEN_DEPS_TREE=true',
            '-e', 'MVN_ARGS=-s /tmp/home/.m2/settings.xml -Dscope=runtime -DskipTests -Dmaven.test.skip=true',
            '-e', 'MAVEN_OPTS=-XX:ActiveProcessorCount=2 -Xmx1536m -Duser.home=/tmp/home',
            '-e', 'GRADLE_USER_HOME=/tmp/home/.gradle', '-e', 'npm_config_cache=/tmp/home/.npm']
        # Docker can inject proxy credentials from the coordinator's client
        # config even without explicit -e. Override every Docker proxy variable.
        for proxy in ('HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'NO_PROXY', 'ALL_PROXY',
                      'http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy', 'all_proxy'):
            args.extend(('-e', proxy + '='))
        args.extend(('--entrypoint', 'sh', image_id, '-c', script))
        try:
            raw = run_command(args, cwd=work, env=environment, timeout=settings.build_timeout,
                max_output_bytes=settings.max_sbom_bytes, input_bytes=source,
                label='cdxgen isolated source analysis')
        finally:
            try:
                run_command([settings.docker_binary, 'rm', '-f', name], cwd=work, env=environment,
                    timeout=30, max_output_bytes=4096, label='Owned source job cleanup')
            except (RuntimeError, OSError):
                pass
    return raw, {'name': 'cdxgen', 'version': VERSION, 'image_id': image_id}, hashlib.sha256(source).hexdigest()


def _validate_result(raw):
    document = json.loads(raw, object_pairs_hook=_unique_keys)
    validate_cyclonedx(document)
    producers = [tool for tool in document.get('metadata', {}).get('tools', {}).get('components', [])
                 if tool.get('name') == 'cdxgen']
    if len(producers) != 1 or producers[0].get('version') != VERSION:
        raise ValueError('Pinned source producer missing or ambiguous')
    if not document.get('components'):
        raise ValueError('Empty source result is not positive dependency coverage')
    return document


def _component_count(document):
    pending = list(document.get('components', []))
    count = 0
    while pending:
        component = pending.pop()
        count += 1
        pending.extend(component.get('components', []))
    return count


def _write(path, document):
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')


def _publish(destination, document, provenance, summary):
    temporary = tempfile.TemporaryDirectory(prefix='.source-publish-', dir=destination.parent)
    cleanup_complete = True
    try:
        staged = Path(temporary.name) / 'result'
        staged.mkdir()
        _write(staged / ARTIFACTS[0], document)
        provenance['source_sbom_sha256'] = hashlib.sha256((staged / ARTIFACTS[0]).read_bytes()).hexdigest()
        _write(staged / ARTIFACTS[1], provenance)
        _write(staged / ARTIFACTS[2], summary)
        commit_directory(staged, destination)
    finally:
        try:
            temporary.cleanup()
        except OSError:
            # This UUID parent is private. Cleanup cannot mask a primary failure
            # or deny downloads after the atomic commit point.
            cleanup_complete = False
    return cleanup_complete


def analyze_source(repository_url, commit, output, *, settings):
    """Publish source artifacts without accepting or waiting for an image.

    A caller may download this immutable directory while a separate image job is
    pending or failed. Unsupported/empty/invalid results are never published.
    """
    started = time.monotonic()
    stage, code = 'source_checkout', 'SOURCE_CHECKOUT_FAILED'
    destination = Path(output).absolute()
    try:
        validate_repository_url(repository_url, settings)
        commit = validate_commit(commit)
        if destination.exists():
            stage, code = 'source_publication', 'SOURCE_PUBLICATION_FAILED'
            raise FileExistsError('Source output already exists')
        with tempfile.TemporaryDirectory(prefix='sbom-source-analysis-') as temporary:
            root = Path(temporary) / 'checkout'
            provenance = checkout(repository_url, commit, root, settings)
            if provenance.get('commit') != commit:
                raise ValueError('Checkout commit mismatch')
            stage, code = 'source_cdxgen', 'SOURCE_UNSUPPORTED'
            types = _project_types(root)
            if not types:
                raise ValueError('No supported source manifests')
            code = 'SOURCE_ENGINE_FAILED'
            raw, engine, source_sha = _engine(root, settings, types)
            stage, code = 'source_validation', 'SOURCE_INVALID_RESULT'
            document = _validate_result(raw)
            summary = {'status': 'completed', 'result_kind': 'source_model', 'scope': SCOPE,
                'project_types': types, 'components': _component_count(document),
                'dependency_entries': len(document.get('dependencies', [])),
                'dependency_edges': sum(len(item.get('dependsOn', []))
                                        for item in document.get('dependencies', [])),
                'original_build_reproduced': False, 'image_presence_verified': False,
                'reference_used_as_input': False,
                'seconds': round(time.monotonic() - started, 3)}
        # Clean project/tool workspaces before the commit point: a later cleanup
        # error must not report failure for an already published source result.
        stage, code = 'source_publication', 'SOURCE_PUBLICATION_FAILED'
        destination.parent.mkdir(parents=True, exist_ok=True)
        provenance.update(engine=engine, input_source_tar_sha256=source_sha, project_types=types,
            source_build_tooling_executed=True, original_build_reproduced=False,
            reference_used_as_input=False, image_input_used=False, scope=SCOPE,
            excluded_directory_names=sorted(IGNORED_DIRECTORIES))
        cleanup_complete = _publish(destination, document, provenance, summary)
        return {'status': 'completed', 'output': str(destination),
                'artifacts': list(ARTIFACTS), 'summary': summary,
                'publication_cleanup': 'complete' if cleanup_complete else 'partial'}
    except SourceAnalysisError:
        raise
    except Exception as error:  # noqa: BLE001 -- fixed source-job boundary, no raw errors escape
        raise SourceAnalysisError(stage, error_type_name(error), code) from None

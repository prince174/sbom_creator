"""Build-enabled cdxgen in an ephemeral job container, without service secrets."""
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from .acquire import clean_environment, run_command
from .build_graph import extract
from .java_resolver import MIRRORS
from .validation import validate_cyclonedx

VERSION = '13.4.0'
SOURCE_LIMIT = 128 * 1024 * 1024
EXCLUDED_DIRECTORIES = frozenset({'.git', 'node_modules', 'target', 'build', '.gradle'})


def source_archive(checkout, *, excluded_directories=EXCLUDED_DIRECTORIES):
    root = Path(checkout).resolve()
    buffer = io.BytesIO()
    total = count = 0
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for directory, names, files in os.walk(root, followlinks=False):
            names[:] = sorted(n for n in names if n not in excluded_directories
                              and not (Path(directory)/n).is_symlink())
            for name in sorted(files):
                path = Path(directory)/name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                    raise ValueError('Unsupported source file for build job')
                count += 1
                total += info.st_size
                relative = path.relative_to(root).as_posix()
                if count > 50_000 or total > SOURCE_LIMIT or any(c in relative for c in '\\:\n\r'):
                    raise ValueError('Build source archive budget/path')
                member = tarfile.TarInfo(relative)
                member.size = info.st_size
                member.mode = 0o755 if info.st_mode & 0o111 else 0o644
                member.uid = member.gid = 65532
                with path.open('rb') as stream:
                    archive.addfile(member, stream)
                if buffer.tell() > SOURCE_LIMIT:
                    raise ValueError('Build source tar budget')
    return buffer.getvalue()


def has_java(checkout):
    for count, (directory, names, files) in enumerate(os.walk(checkout, followlinks=False)):
        if count > 10_000:
            raise ValueError('Java input traversal budget')
        names[:] = [n for n in names if n not in {'.git', 'node_modules', 'target', 'build', '.gradle'}
                    and not (Path(directory)/n).is_symlink()]
        if {'pom.xml', 'build.gradle', 'build.gradle.kts'} & set(files):
            return True
    return False


def generate(checkout, settings):
    if not has_java(checkout):
        return {'status': 'not-applicable', 'profile': 'cdxgen-java-build-v1', 'edges': []}
    if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}', settings.cdxgen_image)
            or settings.java_maven_repository not in MIRRORS):
        raise ValueError('Invalid configured build engine image/repository')
    started = time.monotonic()
    name = 'sbom-build-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='sbom-build-client-') as temporary:
        root = Path(temporary)
        env = clean_environment()
        # Docker connection settings are service-managed, never copied to jobs.
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            if key in os.environ:
                env[key] = os.environ[key]
        image_id = run_command([settings.docker_binary, 'image', 'inspect', settings.cdxgen_image,
            '--format', '{{.Id}}'], cwd=root, env=env, timeout=30, max_output_bytes=4096,
            label='Build engine identity').strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
            raise ValueError('Build engine requires an immutable local image ID')
        source = source_archive(checkout)
        script = ('mkdir -p /tmp/project /tmp/home/.m2 && tar --no-same-owner -xf - -C /tmp/project && '
            "printf '%s' '<settings><localRepository>/tmp/home/.m2/repository</localRepository><mirrors><mirror>"
            '<id>service</id><mirrorOf>*</mirrorOf><url>' + settings.java_maven_repository +
            "</url></mirror></mirrors></settings>' > /tmp/home/.m2/settings.xml && cd /tmp/project && "
            'cdxgen -t java --recurse --spec-version 1.6 --fail-on-error -o /tmp/result.json . '
            '>/tmp/engine.log 2>&1; result=$?; if [ "$result" -ne 0 ]; then exit "$result"; fi; '
            'cat /tmp/result.json')
        args = [settings.docker_binary, 'run', '--rm', '--pull=never', '--name', name, '-i',
            '--read-only', '--user=65532:65532', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=3g', '--cpus=2', '--pids-limit=256', '--tmpfs', '/tmp:rw,size=2147483648',
            '-e', 'HOME=/tmp/home', '-e', 'PREFER_MAVEN_DEPS_TREE=true',
            '-e', 'MVN_ARGS=-s /tmp/home/.m2/settings.xml -Dscope=runtime -DskipTests -Dmaven.test.skip=true',
            '-e', 'MAVEN_OPTS=-XX:ActiveProcessorCount=2 -Xmx1536m -Duser.home=/tmp/home',
            '--entrypoint', 'sh', image_id, '-c', script]
        try:
            raw = run_command(args, cwd=root, env=env, timeout=settings.build_timeout,
                max_output_bytes=settings.max_sbom_bytes, input_bytes=source,
                label='cdxgen isolated build analysis')
        finally:
            # A disconnected CLI can leave a job running; clean only this UUID job.
            try:
                run_command([settings.docker_binary, 'rm', '-f', name], cwd=root, env=env,
                    timeout=30, max_output_bytes=4096, label='Owned build job cleanup')
            except (RuntimeError, OSError):
                pass
        document = json.loads(raw)
        validate_cyclonedx(document)
        tools = document.get('metadata', {}).get('tools', {}).get('components', [])
        if not any(t.get('name') == 'cdxgen' and t.get('version') == VERSION for t in tools):
            raise ValueError('Pinned cdxgen producer missing')
        return {'status': 'evaluated', 'profile': 'cdxgen-java-build-v1', 'build_sbom': document,
                'engine_image_id': image_id, 'engine_version': VERSION,
                'input_source_tar_sha256': hashlib.sha256(source).hexdigest(),
                'seconds': round(time.monotonic()-started, 3), 'source_build_tooling_executed': True,
                'original_build_reproduced': False, 'reference_used_as_input': False,
                'scope': 'Maven runtime dependency resolution (compile+runtime); original image build profiles unknown',
                **extract(document, checkout)}


def resolve(checkout, settings):
    """Build-tool failure must not block the independent image SBOM."""
    if settings.java_backend == 'trivy':
        from .java_resolver import resolve as passive
        return passive(checkout, settings)
    if settings.java_backend == 'disabled':
        return {'status': 'not-applicable', 'profile': 'java-disabled', 'edges': []}
    from .java_resolver import resolve as passive
    attempts = []
    try:
        result = generate(checkout, settings)
        result['tree_status'] = ('PARTIAL' if any(m['status'] == 'UNKNOWN' for m in result.get('modules', []))
                                 else 'RESOLVED') if result['status'] != 'not-applicable' else 'UNKNOWN'
        if result['status'] == 'not-applicable' or result['tree_status'] == 'RESOLVED':
            result['selected_backend'] = 'cdxgen'
            return result
        attempts.append({'engine': 'cdxgen', 'status': 'PARTIAL'})
    except (OSError, ValueError, TypeError, RuntimeError, KeyError, RecursionError) as error:
        attempts.append({'engine': 'cdxgen', 'status': 'UNKNOWN', 'error_type': type(error).__name__})
        result = None
    fallback = passive(checkout, settings)
    attempts.append({'engine': 'trivy', 'status': fallback['status']})
    if result is not None:
        # Conflicting/partial alternatives are visible. Do not union graphs just
        # to increase recall; their owners/scopes first need corroboration.
        result.update(attempts=attempts, fallback=fallback, selected_backend='cdxgen')
        return result
    if fallback['status'] != 'not-applicable':
        fallback.update(attempts=attempts, selected_backend='trivy', image_analysis_blocked=False,
                        tree_status='RESOLVED' if fallback['status'] == 'evaluated' else
                                    'PARTIAL' if fallback['status'] == 'partial' else 'UNKNOWN')
        return fallback
    return {'status': 'UNKNOWN', 'profile': 'cdxgen-java-build-v1', 'edges': [], 'attempts': attempts,
            'tree_status': 'UNKNOWN', 'reason': 'build_model_unavailable_or_budget_exceeded', 'unknown_count': None,
            'original_build_reproduced': False, 'image_analysis_blocked': False}

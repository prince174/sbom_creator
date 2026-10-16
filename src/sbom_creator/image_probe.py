"""Bounded registry availability probe; never run a full scanner while waiting."""
from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from pathlib import Path

from .acquire import clean_environment, image_reference, run_command, secret

VERSIONS = frozenset({'0.22.1', '8a72a424fdecb4caa14f2d525e5d2503331442b5'})
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')


def repository(reference):
    value = reference.split('@', 1)[0]
    return value.rsplit(':', 1)[0] if ':' in value.rsplit('/', 1)[-1] else value


def probe(image, settings):
    """Available returns an immutable reference; failure never claims absence."""
    try:
        reference = image_reference(image, settings)
        username, password = secret('SBOM_REGISTRY_USERNAME'), secret('SBOM_REGISTRY_PASSWORD')
        if bool(username) != bool(password):
            return {'status': 'failed', 'code': 'REGISTRY_CREDENTIALS_INVALID'}
    except (OSError, ValueError, TypeError):
        return {'status': 'failed', 'code': 'REGISTRY_CONFIGURATION_INVALID'}
    try:
        with tempfile.TemporaryDirectory(prefix='sbom-image-probe-') as temporary:
            root = Path(temporary)
            env = clean_environment()
            env.update(HOME=str(root), USERPROFILE=str(root), DOCKER_CONFIG=str(root))
            if username:
                auth = base64.b64encode((username + ':' + password).encode()).decode('ascii')
                config = root / 'config.json'
                config.write_text(json.dumps({'auths': {reference.split('/')[0]: {'auth': auth}}}), encoding='utf-8')
                if os.name != 'nt':
                    config.chmod(0o600)
            version = run_command([settings.crane_binary, 'version'], cwd=root, env=env,
                timeout=min(15, settings.source_image_probe_timeout), max_output_bytes=4096,
                label='Registry probe tool identity').strip().removeprefix('v')
            if version not in VERSIONS:
                return {'status': 'failed', 'code': 'REGISTRY_PROBE_TOOL_INVALID'}
            # Preserve an OCI index digest as the requested subject. The image
            # pipeline separately selects and binds the configured platform.
            digest = run_command([settings.crane_binary, 'digest', reference], cwd=root, env=env,
                timeout=settings.source_image_probe_timeout, max_output_bytes=4096,
                label='Registry availability probe').strip()
            if not DIGEST.fullmatch(digest):
                return {'status': 'failed', 'code': 'REGISTRY_PROBE_IDENTITY_INVALID'}
            immutable = repository(reference) + '@' + digest
            image_reference(immutable, settings)
            return {'status': 'available', 'immutable_image': immutable, 'code': 'REGISTRY_IMAGE_AVAILABLE'}
    except (OSError, ValueError, RuntimeError):
        # Includes unknown network/auth errors: wait is bounded by the workflow
        # deadline. Do not call this a404 or expose a raw subprocess exception.
        return {'status': 'waiting', 'code': 'REGISTRY_AVAILABILITY_UNCONFIRMED'}

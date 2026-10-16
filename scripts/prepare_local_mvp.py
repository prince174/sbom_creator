"""First-time local Docker configuration; never overwrite an existing installation."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'sha256:79857b3a884112f235552efd5a4447a1d7ef00ec399132eba193e8b6cadc0b83'
REGISTRY = 'registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
SOURCE_DB_VOLUME = 'sbom-r111-public-java-1792134539387152100'
WORKSPACE_VOLUME = 'sbom-mvp-local-workspace'
REGISTRY_VOLUME = 'sbom-mvp-local-registry'
DB_SHA = '491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59'
META_SHA = '40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2'


def command(args, *, timeout=60):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        diagnostics = ROOT / 'workspace/local-mvp'
        diagnostics.mkdir(parents=True, exist_ok=True)
        target = diagnostics / ('setup-failure-' + secrets.token_hex(4) + '.log')
        exclusive(target, result.stderr)
        raise RuntimeError('Local setup command failed; private diagnostic retained under workspace/local-mvp')
    return result.stdout


def exclusive(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume-cache', action='store_true', help='Resume only the owned, incomplete cache initialization')
    args = parser.parse_args()
    config = ROOT / '.env.local-mvp'
    private = ROOT / 'secrets/local-mvp'
    if args.resume_cache:
        if not config.is_file() or not (private / 'api-token').is_file():
            raise ValueError('Prepared configuration is required')
        seed_cache()
        return
    if config.exists() or private.exists():
        raise FileExistsError('Existing local configuration must be preserved; use compose start/up')
    for name in (WORKSPACE_VOLUME, REGISTRY_VOLUME):
        probe = subprocess.run(['docker', 'volume', 'inspect', name], capture_output=True, check=False)
        if probe.returncode == 0:
            raise FileExistsError('Existing local volume must be preserved')
    command(['docker', 'image', 'inspect', SERVICE])
    command(['docker', 'image', 'inspect', REGISTRY])
    command(['docker', 'volume', 'inspect', SOURCE_DB_VOLUME])
    openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
    if not Path(openssl).is_file():
        raise FileNotFoundError('OpenSSL is required for the isolated local registry CA')
    ca, server, trust = private / 'private-ca', private / 'registry', private / 'trust'
    for directory in (ca, server, trust, private / 'credentials'):
        directory.mkdir(parents=True, exist_ok=False)
    command([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
        '-subj', '/CN=SBOM Local MVP CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', str(ca / 'ca.key'), '-out', str(ca / 'ca.crt')])
    command([openssl, 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=registry',
        '-keyout', str(server / 'registry.key'), '-out', str(ca / 'registry.csr')])
    extensions = ca / 'server.ext'
    exclusive(extensions, b'subjectAltName=DNS:registry,DNS:localhost,IP:127.0.0.1\n'
        b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
        b'extendedKeyUsage=serverAuth\n')
    command([openssl, 'x509', '-req', '-in', str(ca / 'registry.csr'),
        '-CA', str(ca / 'ca.crt'), '-CAkey', str(ca / 'ca.key'), '-CAcreateserial',
        '-out', str(server / 'registry.crt'), '-days', '90', '-sha256', '-extfile', str(extensions)])
    system_ca = command(['docker', 'run', '--rm', '--network=none', '--read-only',
        '--cap-drop=ALL', '--entrypoint=python', SERVICE, '-c',
        "from pathlib import Path;import sys;sys.stdout.buffer.write(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes())"])
    exclusive(trust / 'local-ca.crt', (ca / 'ca.crt').read_bytes())
    exclusive(trust / 'ca-bundle.pem', system_ca + b'\n' + (ca / 'ca.crt').read_bytes())
    exclusive(private / 'api-token', (secrets.token_urlsafe(48) + '\n').encode())
    if os.name != 'nt':
        for path in (private / 'api-token', ca / 'ca.key', server / 'registry.key'):
            path.chmod(0o600)
    # Credentials are not placed in env, argv, a committed file, or setup output.
    exclusive(config, ('SBOM_LOCAL_SERVICE_IMAGE=' + SERVICE + '\n'
        'SBOM_LOCAL_REGISTRY_IMAGE=' + REGISTRY + '\n'
        'SBOM_REGISTRY_HOSTS=registry:5000,ghcr.io,docker.io,registry-1.docker.io\n').encode())
    for name in (WORKSPACE_VOLUME, REGISTRY_VOLUME):
        command(['docker', 'volume', 'create', '--label', 'sbom-creator.local-mvp=true', name])
    seed_cache()


def seed_cache():
    output = ROOT / 'workspace/local-mvp'
    output.mkdir(parents=True, exist_ok=True)
    if (output / 'setup.json').exists():
        raise FileExistsError('Completed cache setup must not be repeated')
    for name in (WORKSPACE_VOLUME, REGISTRY_VOLUME):
        info = json.loads(command(['docker', 'volume', 'inspect', name]))[0]
        if info.get('Labels', {}).get('sbom-creator.local-mvp') != 'true':
            raise ValueError('Only this setup owned volumes may be initialized')
    # CHOWN is used only for the two new volume roots; data copy runs as UID10001.
    command(['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
        '--cap-add=CHOWN', '--security-opt=no-new-privileges', '--user=0:0', '--entrypoint=python',
        '--mount', 'type=volume,src=' + WORKSPACE_VOLUME + ',dst=/workspace',
        '--mount', 'type=volume,src=' + REGISTRY_VOLUME + ',dst=/registry-data',
        SERVICE, '-c', "import os;os.chown('/workspace',10001,10001);os.chown('/registry-data',10001,10001)"])
    program = r'''
import hashlib,json,shutil
from pathlib import Path
source=Path('/public-cache/trivy-cache/java-db')
target=Path('/workspace/trivy-cache/java-db')
target.mkdir(parents=True,exist_ok=False)
expected={'trivy-java.db':DB_SHA,'metadata.json':META_SHA}
facts={}
for name,digest in expected.items():
    with (source/name).open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==digest
    with (source/name).open('rb') as incoming,(target/name).open('xb') as outgoing:
        shutil.copyfileobj(incoming,outgoing,1024*1024)
    with (target/name).open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==digest
    facts[name]={'sha256':digest,'bytes':(target/name).stat().st_size}
print(json.dumps({'status':'passed','copied_public_database':facts,'source_volume_read_only':True}))
'''.replace('DB_SHA', repr(DB_SHA)).replace('META_SHA', repr(META_SHA))
    result = command(['docker', 'run', '--rm', '--network=none', '--read-only',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=10001:10001',
        '--memory=128m', '--cpus=2', '--entrypoint=python',
        '--mount', 'type=volume,src=' + SOURCE_DB_VOLUME + ',dst=/public-cache,readonly',
        '--mount', 'type=volume,src=' + WORKSPACE_VOLUME + ',dst=/workspace',
        SERVICE, '-c', program], timeout=120)
    exclusive(output / 'setup.json', result)
    print(json.dumps({'status': 'prepared', 'api': 'http://127.0.0.1:18082',
        'token_file': 'secrets/local-mvp/api-token', 'token_printed': False,
        'existing_services_changed': False, 'database_downloaded': False}))


if __name__ == '__main__':
    main()

"""External loopback registry tag-race fixture; production settings unchanged."""
import hashlib
import json
import secrets
import tempfile
import time
from pathlib import Path

from http_integration import command, free_port
from run import ROOT, atomic_json

from sbom_creator.acquire import Settings, clean_environment, run_command
from sbom_creator.payload import SyftFiles
from sbom_creator.scanner import TRUSTED_CONFIG, _image_identity


def scan(reference, expected=None, *, ca=None, password=None, auth_authority=None):
    authority = reference.split('/')[0]
    if not authority.startswith('localhost:'):
        raise ValueError('Loopback fixture only')
    with tempfile.TemporaryDirectory(prefix='sbom-registry-r49-') as folder:
        config = Path(folder) / 'syft.yaml'
        registry = ('\nregistry:\n  ca-cert: ' + json.dumps(str(ca)) + '\n'
                    if ca else '\nregistry:\n  insecure-use-http: true\n')
        config.write_text(TRUSTED_CONFIG + registry +
                          'file:\n  metadata:\n    selection: all\n  content:\n'
                          '    skip-files-above-size: 33554432\n'
                          '    globs: ["/application/hey"]\n', encoding='utf-8')
        env = clean_environment()
        env.update(TEMP=folder, TMP=folder, TMPDIR=folder, DOCKER_CONFIG=folder)
        if password is not None:
            env.update(SYFT_REGISTRY_AUTH_AUTHORITY=auth_authority or authority,
                       SYFT_REGISTRY_AUTH_USERNAME='fixture', SYFT_REGISTRY_AUTH_PASSWORD=password)
        raw = run_command([str(ROOT / '.tools/syft/syft.exe'), 'scan', 'registry:' + reference,
                           '--platform', 'linux/amd64', '--scope', 'squashed',
                           '--override-default-catalogers', 'image', '-o', 'syft-json',
                           '--config', str(config)], cwd=Path(folder), env=env,
                          timeout=180, max_output_bytes=64 * 1024 * 1024, label='R49 registry scan')
    data = json.loads(raw)
    if data['descriptor']['version'] != '1.51.1':
        raise ValueError('Unexpected scanner')
    identity = _image_identity(data, reference, Settings(registry_hosts=(authority,)))
    if expected and identity['image_config_digest'] != expected:
        raise ValueError('Rescanned image differs')
    payload = SyftFiles(data).read('/application/hey')
    if payload is None:
        raise ValueError('Payload unavailable')
    return identity, hashlib.sha256(payload).hexdigest()


def main():
    suffix = secrets.token_hex(6)
    port = free_port()
    target = f'localhost:{port}/fixture/hey:mutable'
    registry_image = command(['docker', 'image', 'inspect', 'registry:2.8.3', '--format', '{{.Id}}'])
    container = command(['docker', 'run', '-d', '--name', 'sbom-r49-' + suffix,
                         '--memory=256m', '--cpus=1', '-p', f'127.0.0.1:{port}:5000', registry_image])
    try:
        time.sleep(2)
        for source in ('paired-hey-v1', 'go-multimain-r39'):
            image = (ROOT / 'benchmarks/.work' / source / 'runtime.id').read_text().strip()
            command(['docker', 'tag', image, target])
            command(['docker', 'push', target], timeout=180)
            if source == 'paired-hey-v1':
                original, original_sha = scan(target)
            else:
                changed, changed_sha = scan(target)
        if changed['image_config_digest'] == original['image_config_digest']:
            raise AssertionError('Fixture tag did not change')
        try:
            scan(target, original['image_config_digest'])
        except ValueError as error:
            if str(error) != 'Rescanned image differs':
                raise
        else:
            raise AssertionError('Mutable tag race accepted')
        pinned, pinned_sha = scan(original['immutable_reference'], original['image_config_digest'])
        if pinned_sha != original_sha or changed_sha == original_sha:
            raise AssertionError('Pinned payload differs or replacement unchanged')
        atomic_json(ROOT / 'docs/go-registry-identity-v1.json', {
            'experiment': 'R49', 'registry_image_id': registry_image,
            'original_config_digest': original['image_config_digest'],
            'replacement_config_digest': changed['image_config_digest'],
            'original_manifest_digest': pinned['image_digest'],
            'original_payload_sha256': original_sha, 'replacement_payload_sha256': changed_sha,
            'mutable_tag_mismatch_rejected': True, 'pinned_original_payload_retained': True,
            'authentication_tested': False, 'transport': 'isolated loopback HTTP fixture only',
            'runtime_changed': False, 'direct_accuracy': None})
        print('R49 passed: registry payload, mutable tag rejection, immutable digest rescan')
    finally:
        command(['docker', 'rm', '-f', container])


if __name__ == '__main__':
    main()

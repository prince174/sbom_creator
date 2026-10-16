"""Publish two existing controlled image archives to the local HTTPS registry."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tarfile

from prepare_local_mvp import ROOT, SERVICE

SAMPLES = {
    'java-rest': ('benchmarks/.work/paired-petclinic-rest-v1/image.tar',
        'a3e10a0826115dba68519a6a90c9a7c17ab18d34ee11a3ca673633035797adea'),
    'javascript-nest': ('benchmarks/.work/no-lock-expanded-v1/paired-nest-starter-v1/image.tar',
        '32d2a190cbce31823071df29d387ef9f0f6013f44a6e0511e7fdee202b642433'),
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def oci_layout(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(source) as archive:
        members = {}
        for member in archive.getmembers():
            if member.name in members:
                raise ValueError('Duplicate OCI archive member')
            members[member.name] = member

        def metadata(name):
            member = members[name]
            if not member.isfile() or member.size > 8 * 1024**2:
                raise ValueError('Invalid OCI metadata')
            return archive.extractfile(member).read(member.size + 1)

        def descriptor_blob(descriptor):
            digest = descriptor['digest']
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
                raise ValueError('Invalid OCI digest')
            raw = metadata('blobs/sha256/' + digest[7:])
            if len(raw) != descriptor['size'] or hashlib.sha256(raw).hexdigest() != digest[7:]:
                raise ValueError('OCI descriptor binding mismatch')
            return raw

        root = json.loads(metadata('index.json'))['manifests']
        if len(root) != 1:
            raise ValueError('Expected one controlled image index')
        index = json.loads(descriptor_blob(root[0]))
        candidates = [entry for entry in index['manifests']
            if entry.get('platform', {}).get('os') == 'linux'
            and entry.get('platform', {}).get('architecture') == 'amd64']
        if len(candidates) != 1:
            raise ValueError('Expected one linux/amd64 platform')
        platform = candidates[0]
        manifest = json.loads(descriptor_blob(platform))
        descriptors = [platform, manifest['config'], *manifest['layers']]
        for descriptor in descriptors:
            digest = descriptor['digest']
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
                raise ValueError('Invalid OCI digest')
            name = 'blobs/sha256/' + digest[7:]
            member = members[name]
            if not member.isfile() or member.size != descriptor['size'] or member.size > 2 * 1024**3:
                raise ValueError('Invalid OCI blob')
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                continue
            digest_observed = hashlib.sha256()
            with archive.extractfile(member) as incoming, path.open('xb') as outgoing:
                while chunk := incoming.read(1024 * 1024):
                    outgoing.write(chunk)
                    digest_observed.update(chunk)
            if digest_observed.hexdigest() != digest[7:]:
                raise ValueError('Physical OCI blob SHA256 mismatch')
        (destination / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding='utf-8')
        (destination / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [platform]}) + '\n', encoding='utf-8')
        return {'platform_digest': platform['digest'], 'config_digest': manifest['config']['digest'],
            'layer_digests': [item['digest'] for item in manifest['layers']]}


def crane(layout, *args):
    command = ['docker', 'run', '--rm', '--network=sbom-mvp-local_default', '--read-only',
        '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--memory=512m', '--cpus=2', '--env=SSL_CERT_FILE=/trust/ca-bundle.pem',
        '--mount', 'type=bind,src=' + str(layout) + ',dst=/input,readonly',
        '--mount', 'type=bind,src=' + str(ROOT / 'secrets/local-mvp/trust') + ',dst=/trust,readonly',
        '--entrypoint=crane', SERVICE, *args]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180, check=False)
    if result.returncode:
        (layout / 'push-failure.log').write_bytes(result.stderr)
        raise RuntimeError('Local registry transfer failed; private diagnostic preserved')
    return result.stdout.decode().strip()


def main():
    target = ROOT / 'workspace/local-mvp/samples.json'
    if target.exists():
        raise FileExistsError('Preserve completed sample publication')
    reports = {}
    for name, (relative, expected) in SAMPLES.items():
        source = ROOT / relative
        if sha(source) != expected:
            raise ValueError('Controlled image archive changed')
        layout = ROOT / 'workspace/local-mvp/oci' / name
        binding = oci_layout(source, layout)
        tag = 'registry:5000/' + name + ':demo'
        crane(layout, 'push', '/input', tag)
        published = crane(layout, 'digest', tag)
        if published != binding['platform_digest']:
            raise ValueError('Local distribution changed the exact platform manifest')
        config = json.loads(crane(layout, 'manifest', tag))['config']['digest']
        if config != binding['config_digest']:
            raise ValueError('Local distribution changed image config')
        reports[name] = {'image': tag.split(':demo')[0] + '@' + published,
            'archive': relative, 'archive_sha256': expected, **binding,
            'manifest_preserved': True, 'config_preserved': True,
            'reference_or_source_accessed': False}
        print(json.dumps({'published': name, 'image': reports[name]['image']}), flush=True)
    with target.open('x', encoding='utf-8') as stream:
        json.dump({'status': 'passed', 'samples': reports, 'foreign_project_built': False}, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()

"""Experimental bounded Syft final-file contents; no runtime scanner change."""
import base64
import hashlib
import json
import re
import tempfile
from pathlib import Path

from run import ROOT, atomic_json

from sbom_creator.acquire import Settings, clean_environment, run_command
from sbom_creator.payload import SyftFiles
from sbom_creator.scanner import TRUSTED_CONFIG, _image_identity


def read_payload(archive, path, config_digest):
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', path) or '..' in path.split('/'):
        raise ValueError('Unsupported exact binary path')
    settings = Settings(registry_hosts=('docker.io',), image_archive=str(archive))
    with tempfile.TemporaryDirectory(prefix='sbom-go-bridge-') as directory:
        config = Path(directory) / 'syft.yaml'
        config.write_text(TRUSTED_CONFIG + '\nfile:\n  metadata:\n    selection: all\n  content:\n'
                          '    skip-files-above-size: 33554432\n    globs: [' + json.dumps(path) + ']\n', encoding='utf-8')
        env = clean_environment()
        env.update(TEMP=directory, TMP=directory, TMPDIR=directory, DOCKER_CONFIG=directory)
        raw = run_command([str(ROOT / '.tools/syft/syft.exe'), 'scan', 'docker-archive:' + str(archive),
                           '--platform', 'linux/amd64', '--override-default-catalogers', 'image',
                           '--scope', 'squashed', '-o', 'syft-json', '--config', str(config)],
                          cwd=Path(directory), env=env, timeout=300, max_output_bytes=64 * 1024 * 1024,
                          label='Syft Go payload bridge')
    data = json.loads(raw)
    identity = _image_identity(data, 'docker.io/sbom-creator-benchmark/go-payload:v1', settings)
    if identity['image_config_digest'] != config_digest:
        raise ValueError('Rescanned image differs')
    if data['descriptor']['version'] != '1.51.1':
        raise ValueError('Unexpected Syft version')
    files = SyftFiles(data)
    payload = files.read(path)
    if payload is None:
        raise ValueError('Binary unavailable within content budget')
    return payload, data, len(raw.encode('utf-8'))


def main():
    rows = []
    for project, ref, path in [('paired-hey-v1', 'paired-hey-v1', '/application/hey'),
                               ('paired-lazygit-v1', 'paired-lazygit-v1', '/application/lazygit')]:
        work = ROOT / 'benchmarks/.work' / project
        original = json.loads((work / 'analysis/image.syft.json').read_bytes())
        # Expected identity comes from the existing image input, not reference build info.
        raw_config = base64.b64decode(original['source']['metadata']['config'], validate=True)
        digest = 'sha256:' + hashlib.sha256(raw_config).hexdigest()
        payload, fresh, output_bytes = read_payload(work / 'image.tar', path, digest)
        same = fresh['artifacts'] == original['artifacts'] and fresh['artifactRelationships'] == original['artifactRelationships']
        if not same:
            raise ValueError('Inventory/graph changed')
        # Oracle only confirms payload after reading it through Syft.
        reference = ROOT / 'benchmarks/references' / ref
        if hashlib.sha256(payload).hexdigest() != (reference / 'binary.sha256').read_text().split()[0]:
            raise ValueError('Payload differs from paired binary')
        rows.append({'project': project, 'bytes': len(payload), 'private_syft_json_bytes': output_bytes,
                     'payload_sha256': hashlib.sha256(payload).hexdigest(), 'inventory_graph_unchanged': same})
    atomic_json(ROOT / 'docs/syft-go-payload-v1.json', {'experiment': 'R45', 'rows': rows,
                'runtime_changed': False, 'direct_accuracy': None,
                'limitation': 'Archive backend tested; registry credentials, multilayer and general paths need separate checks'})
    print(json.dumps(rows))


if __name__ == '__main__':
    main()

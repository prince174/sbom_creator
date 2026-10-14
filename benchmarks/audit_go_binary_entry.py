"""Read one-layer OCI binary payload; no reference build-info used as input."""
import hashlib
import io
import json
import subprocess
import tarfile

from paired_express import archive_binding, sha
from run import ROOT, atomic_json


def main():
    output = ROOT / 'benchmarks/.work/go-binary-info-r41'
    helper = output / 'info.exe'
    rows = []
    for name, reference in [('paired-hey-v1', 'paired-hey-v1'), ('go-multimain-r39', 'go-multimain-v2')]:
        work = ROOT / 'benchmarks/.work' / name
        scanned = json.loads((work / 'analysis/image.syft.json').read_bytes())
        owners = [a for a in scanned['artifacts'] if a.get('metadata', {}).get('goBuildSettings')]
        if len(owners) != 1 or len(owners[0]['locations']) != 1:
            raise ValueError('Ambiguous binary owner')
        path = owners[0]['locations'][0]['path'].lstrip('/')
        index = (work / 'runtime.id').read_text().strip()
        binding = archive_binding(work / 'image.tar', index)
        with tarfile.open(work / 'image.tar') as archive:
            manifest = json.load(archive.extractfile('blobs/sha256/' + binding['platform_manifest_digest'].split(':')[1]))
            if len(manifest['layers']) != 1:
                raise ValueError('Only one-layer fixtures supported')
            descriptor = manifest['layers'][0]
            layer = archive.extractfile('blobs/sha256/' + descriptor['digest'].split(':')[1]).read(128 * 1024 * 1024 + 1)
            if len(layer) > 128 * 1024 * 1024 or len(layer) != descriptor['size'] or 'sha256:' + hashlib.sha256(layer).hexdigest() != descriptor['digest']:
                raise ValueError('Layer budget/hash mismatch')
            with tarfile.open(fileobj=io.BytesIO(layer), mode='r:*') as files:
                targets = []
                for number, member in enumerate(files):
                    if number >= 10000:
                        raise ValueError('Layer entry budget exceeded')
                    if member.name.removeprefix('./') == path:
                        targets.append(member)
                if len(targets) != 1 or not targets[0].isfile() or targets[0].size > 64 * 1024 * 1024:
                    raise ValueError('Unsupported payload')
                payload = files.extractfile(targets[0]).read()
        binary = output / (name + '.binary')
        binary.write_bytes(payload)
        info = json.loads(subprocess.check_output([str(helper), str(binary)], timeout=30))
        settings = {s['Key']: s['Value'] for s in info['Settings']}
        if settings.get('vcs.modified') != 'false':
            raise ValueError('Dirty binary')
        module = info['Main']['Path']
        entry = info['Path']
        relative = '.' if entry == module else entry.removeprefix(module + '/') if entry.startswith(module + '/') else None
        if relative is None or '..' in relative.split('/'):
            raise ValueError('Entry outside module')
        # Reference binding is checked only after reading the binary entry.
        receipt = json.loads((ROOT / 'benchmarks/references' / reference / 'receipt.json').read_bytes())
        if binding != receipt['image_binding'] or settings.get('vcs.revision') != receipt['commit']:
            raise ValueError('Fixture provenance differs')
        rows.append({'project': name, 'entry_import_path': entry, 'main_module': module,
                     'source_directory_candidate': relative, 'binary_sha256': hashlib.sha256(payload).hexdigest(),
                     'image_binding': binding, 'binary_commit': settings['vcs.revision']})
    report = {'experiment': 'R41', 'rows': rows, 'helper_sha256': sha(helper),
              'helper_source_sha256': sha(ROOT / 'benchmarks/go_binary_info.go'),
              'runtime_changed': False, 'direct_accuracy': None,
              'limitation': 'Entry selection only; one-layer bounded fixture reader, no import graph or runtime integration'}
    atomic_json(ROOT / 'docs/go-binary-entry-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

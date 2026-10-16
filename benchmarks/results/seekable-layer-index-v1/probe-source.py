"""Physical header access only; no classifier or evaluation labels read."""
import hashlib
import json
import time

from run import ROOT, atomic_json
from seekable_layer_index import Layers


def main():
    work = ROOT / 'benchmarks/.work/paired-dropwizard-reactor-v1'
    output = ROOT / 'benchmarks/results/seekable-layer-index-v1'
    if output.exists():
        raise FileExistsError('Preserve attempted probe')
    catalog_path = work / 'analysis-cached-evidence-input-v3/image.syft.json'
    atomic_json(output / 'candidate-freeze.json', {'oracle_read': False, 'runtime_changed': False,
        'mode': 'Disclosed physical-index development, not a payload/accuracy prediction',
        'code_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
            'benchmarks/seekable_layer_index.py', 'benchmarks/check_seekable_layer_index.py')},
        'catalog_sha256': hashlib.sha256(catalog_path.read_bytes()).hexdigest()})
    document = json.loads(catalog_path.read_bytes())
    reader = Layers(work / 'image.tar')
    started = time.monotonic()
    rows = []
    try:
        if reader.config_digest != document['source']['metadata']['imageID']:
            raise ValueError('Catalog config binding differs')
        for item in document.get('files', []):
            location, metadata = item['location'], item.get('metadata', {})
            if metadata.get('type') != 'RegularFile' or not location['path'].endswith('.jar'):
                continue
            view = reader.view(location['path'], location['layerID'], metadata['size'])
            prefix = view.read(4)
            rows.append({'path': location['path'], 'layer': location['layerID'],
                         'size': metadata['size'], 'first_four_bytes': prefix.hex()})
        atomic_json(output / 'report.json', {'oracle_read': False, 'runtime_changed': False,
                    'seconds': time.monotonic()-started, 'rows': rows, 'stats': reader.stats,
                    'image_config_digest': reader.config_digest,
                    'limitations': ['Only ZIP header bytes, NOT class/resource payload or Maven identity proof',
                                    'No classifier integration, final SBOM or accuracy gain claimed',
                                    'New separate 8GiB internal normalization disk budget; metadata16MiB, per-read32MiB/total128MiB',
                                    'Original R96/R100 limits/code unchanged; no production adoption or hard filesystem quota']})
        print(json.dumps({'files': len(rows), 'seconds': time.monotonic()-started, 'stats': reader.stats}))
    finally:
        reader.close()


if __name__ == '__main__':
    main()

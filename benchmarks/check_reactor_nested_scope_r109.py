"""Verify new post-only labels against immutable inputs and sealed manifests."""
import hashlib
import json

from label_reactor_nested_scope_r109 import OUTPUT
from label_reactor_packaged_scope_r108 import labels, read, sha
from run import ROOT, atomic_json


def main():
    result = OUTPUT / 'verification.json'
    if result.exists():
        raise FileExistsError('Preserve completed verification')
    manifest = read(OUTPUT / 'input-manifest.json')
    report = read(OUTPUT / 'report.json')
    if sha(OUTPUT / 'executed-script.py') != manifest['script_sha256']:
        raise ValueError('Executed label source differs from sealed hash')
    for relative, expected in manifest['dependency_sha256'].items():
        if sha(ROOT / relative) != expected:
            raise ValueError('Label dependency changed after execution')
    checks, archives, rows = 0, 0, 0
    for summary in report['reports']:
        name = summary['pair']
        pair = ROOT / 'benchmarks/references' / name
        pair_path = OUTPUT / (name + '.json')
        if sha(pair_path) != manifest['output_reports'][pair_path.name] or read(pair_path) != summary:
            raise ValueError('Pair label differs from sealed aggregate')
        for relative, expected in manifest['inputs'][name]['reference_hashes'].items():
            if sha(ROOT / relative) != expected:
                raise ValueError('Immutable reference changed')
        expected_modules = labels(pair, read(pair / 'application-tree.json'))
        for module, expected in zip(summary['modules'], expected_modules, strict=True):
            for key in ('path', 'owner', 'image_prefix', 'known_file_labels',
                        'unknown_standalone_files', 'known_standalone_coordinate_set'):
                if module[key] != expected[key]:
                    raise ValueError('Standalone controlled-hash labels not independently reproduced')
            known = {row['coordinate'] for row in module['known_file_labels'] + module['nested_file_labels']}
            if sorted(known) != module['known_delivered_coordinate_set']:
                raise ValueError('Delivered coordinate set differs from independent physical label union')
            if module['unknown_shaded_content'] and module['complete_image_component_scope_attested']:
                raise ValueError('Opaque primary cannot attest full component scope')
            checks += 1
        inventory_path = OUTPUT / summary['archive_inventory_file']
        if sha(inventory_path) != summary['archive_inventory_sha256']:
            raise ValueError('Complete entry inventory seal failed')
        inventory = json.loads(inventory_path.read_bytes())['archives_by_complete_sha256']
        for digest, archive in inventory.items():
            raw = json.dumps(archive['entries'], sort_keys=True, separators=(',', ':')).encode()
            if (digest != archive['sha256'] or len(archive['entries']) != archive['entry_count']
                    or hashlib.sha256(raw).hexdigest() != archive['inventory_sha256']):
                raise ValueError('Complete archive entry inventory binding failed')
            if any(row.get('entry_crc_verified') is not True for row in archive['entries'] if not row['directory']):
                raise ValueError('Unverified regular entry included')
            archives += 1
            rows += len(archive['entries'])
    atomic_json(result, {'status': 'PASS', 'post_only': True,
        'prediction_or_classifier_inputs_read': False,
        'independently_reproduced_standalone_owner_labels': checks,
        'sealed_complete_archive_inventories': archives, 'hashed_entry_rows': rows,
        'report_sha256': sha(OUTPUT / 'report.json'),
        'input_manifest_sha256': sha(OUTPUT / 'input-manifest.json'),
        'checker_sha256': sha(__file__),
        'limitations': 'This manifest check is not another physical scan, a publisher authentication or a shaded-component identity proof'})
    print(checks, archives, rows, flush=True)


if __name__ == '__main__':
    main()

"""Explain R62 missing associations without changing candidate rules."""
import json
import tomllib

from audit_fd_declarations import declarations
from run import ROOT, atomic_json


def main():
    work = ROOT / 'benchmarks/.work/paired-fd-v1'
    source_rows = declarations((work / 'src/Cargo.toml').read_bytes())
    lock = tomllib.loads((work / 'src/Cargo.lock').read_text())
    image = json.loads((work / 'analysis/image.syft.json').read_bytes())
    rows = []
    for name in ('nix', 'version_check'):
        declared = [r for r in source_rows if r['name'] == name]
        locked = sorted({p['version'] for p in lock['package'] if p['name'] == name})
        installed = sorted({p['version'] for p in image['artifacts'] if p['type'] == 'rust-crate' and p['name'] == name})
        rows.append({'name': name, 'source_declarations': declared,
                     'lock_versions': locked, 'image_versions': installed,
                     'association_status': 'UNKNOWN', 'direct_edge_proven': False})
    if rows[0]['lock_versions'] != ['0.24.3', '0.29.0'] or rows[0]['image_versions'] != rows[0]['lock_versions']:
        raise ValueError('Nix ambiguity evidence changed')
    if rows[1]['image_versions'] or rows[1]['source_declarations'][0]['scope'] != 'build':
        raise ValueError('Build-only absence evidence changed')
    atomic_json(ROOT / 'docs/fd-unknowns-v1.json', {'experiment': 'R63', 'rows': rows,
        'runtime_changed': False, 'rules_changed': False, 'direct_accuracy': None,
        'conclusion': 'Do not choose a version by name or require build dependencies to survive in the runtime image'})
    print('R63: nix multiple identities; version_check declared build-only and absent from image')


if __name__ == '__main__':
    main()

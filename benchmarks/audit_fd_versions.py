"""Conservative version association experiment, never direct-edge proof."""
import json
import tomllib
from collections import defaultdict

from audit_fd_declarations import declarations
from run import ROOT, atomic_json


def associate(rows, lock, image):
    locked, installed = defaultdict(set), defaultdict(set)
    for package in lock['package']:
        locked[package['name']].add((package['version'], package.get('source')))
    for package in image['artifacts']:
        if package.get('type') == 'rust-crate':
            installed[package['name']].add(package['version'])
    result = []
    for row in rows:
        matches = locked[row['name']]
        versions = installed[row['name']]
        value = dict(row, status='UNKNOWN', reason='ambiguous_or_missing_lock_image_version')
        if len(matches) == 1 and len(versions) == 1:
            version, source = next(iter(matches))
            if version in versions and source == 'registry+https://github.com/rust-lang/crates.io-index' and not row['workspace_inherited']:
                value.update(status='DECLARED_PRESENT_VERSION_CANDIDATE', reason=None,
                             resolved_version=version, direct_edge_proven=False)
        result.append(value)
    return result


def main():
    work = ROOT / 'benchmarks/.work/paired-fd-v1'
    rows = declarations((work / 'src/Cargo.toml').read_bytes())
    lock = tomllib.loads((work / 'src/Cargo.lock').read_text())
    image = json.loads((work / 'analysis/image.syft.json').read_bytes())
    predicted = associate(rows, lock, image)
    # Evaluation-only reference opened after association.
    ref = ROOT / 'benchmarks/references/paired-fd-v1'
    bom = json.loads((ref / 'sbom.json').read_bytes())
    components = {c['bom-ref']: c for c in bom['components']}
    labels = json.loads((ref / 'direct-edge-kinds.json').read_bytes())
    actual = {(r['name'], r['resolved_version']) for r in predicted if r['status'] != 'UNKNOWN'}
    expected = {(components[r['ref']]['name'], components[r['ref']]['version']) for r in labels}
    atomic_json(ROOT / 'docs/fd-versions-v1.json', {'experiment': 'R62', 'rows': predicted,
        'association_matches_reference_edges': len(actual & expected),
        'reference_edges_without_association': sorted(expected - actual),
        'associations_outside_reference': sorted(actual - expected), 'runtime_changed': False,
        'direct_accuracy': None, 'limitation': 'Presence/version association only; target/feature activation and direct build edges unproven'})
    print(f'R62 associations: {len(actual)}, reference overlap: {len(actual & expected)}, missing: {len(expected - actual)}')


if __name__ == '__main__':
    main()

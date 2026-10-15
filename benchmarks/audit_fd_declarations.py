"""Evaluation-only manifest ownership/scope audit; no version resolution."""
import hashlib
import json
import tomllib

from run import ROOT, atomic_json


def declarations(raw):
    document = tomllib.loads(raw.decode('utf-8'))
    owner = document.get('package', {}).get('name')
    if not isinstance(owner, str):
        raise TypeError('Root package owner unavailable')
    rows = []
    def collect(table, target=None):
        for section, scope in [('dependencies', 'normal'), ('build-dependencies', 'build'), ('dev-dependencies', 'dev')]:
            for alias, value in table.get(section, {}).items():
                details = {'version': value} if isinstance(value, str) else value
                rows.append({'owner': owner, 'alias': alias, 'name': details.get('package', alias),
                             'scope': scope, 'target': target, 'optional': details.get('optional', False),
                             'version_requirement': details.get('version'),
                             'workspace_inherited': details.get('workspace', False),
                             'build_activation': 'UNKNOWN', 'resolved_version': None})
    collect(document)
    for target, table in document.get('target', {}).items():
        collect(table, target)
    return rows


def main():
    source = ROOT / 'benchmarks/.work/paired-fd-v1/src/Cargo.toml'
    rows = declarations(source.read_bytes())
    # Evaluation data opened after source-only extraction.
    ref = ROOT / 'benchmarks/references/paired-fd-v1'
    receipt = json.loads((ref / 'receipt.json').read_bytes())
    if hashlib.sha256(source.read_bytes()).hexdigest() != receipt['reference_hashes']['Cargo.toml']:
        raise ValueError('Source manifest differs')
    bom = json.loads((ref / 'sbom.json').read_bytes())
    components = {c['bom-ref']: c for c in bom['components']}
    edges = json.loads((ref / 'direct-edge-kinds.json').read_bytes())
    matches = []
    for edge in edges:
        component = components[edge['ref']]
        matched = [r for r in rows if r['name'] == component['name'] and
                   any(r['scope'] == (k['kind'] or 'normal') and r['target'] == k['target'] for k in edge['dep_kinds'])]
        matches.append({'name': component['name'], 'reference_version': component['version'],
                        'declaration_matches': len(matched)})
    if any(r['declaration_matches'] != 1 for r in matches):
        raise ValueError('Ambiguous or missing declaration match')
    atomic_json(ROOT / 'docs/fd-declarations-v1.json', {'experiment': 'R61', 'declarations': rows,
        'reference_matches': matches, 'direct_accuracy': None, 'runtime_changed': False,
        'limitation': 'Declaration association only; requirements are not resolved versions and activation stays UNKNOWN'})
    print(f'R61: {len(rows)} declarations; {len(matches)} reference edges uniquely associated')


if __name__ == '__main__':
    main()

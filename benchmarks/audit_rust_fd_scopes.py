"""Evaluation-only Rust root edge kinds; no target activation inference."""
import hashlib
import json
from collections import Counter

from paired_express import root_dependencies
from run import ROOT, atomic_json


def main():
    ref = ROOT / 'benchmarks/references/build-v1/rust-fd'
    bom_raw = (ref / 'sbom.json').read_bytes()
    provenance = json.loads((ref / 'provenance.json').read_bytes())
    if hashlib.sha256(bom_raw).hexdigest() != provenance['reference']['sha256']:
        raise ValueError('Reference changed')
    metadata_path = ROOT / 'benchmarks/results/build-references-v1/rust-fd/artifacts/resolved.json'
    metadata_raw = metadata_path.read_bytes()
    data = json.loads(metadata_raw)
    bom = json.loads(bom_raw)
    root = bom['metadata']['component']['bom-ref']
    node = next(n for n in data['resolve']['nodes'] if n['id'] == root)
    packages = {p['id']: p for p in data['packages']}
    deps = {d['pkg']: d for d in node['deps']}
    rows = []
    for edge in root_dependencies(bom):
        dep = deps.get(edge)
        package = packages.get(edge)
        rows.append({'ref': edge, 'name': package['name'] if package else None,
                     'version': package['version'] if package else None,
                     'dep_kinds': dep['dep_kinds'] if dep else None,
                     'build_activation': 'UNKNOWN'})
    report = {'experiment': 'R58', 'project': 'rust-fd', 'rows': rows,
              'root_edges': len(rows), 'mapped_edges': sum(r['dep_kinds'] is not None for r in rows),
              'kind_occurrences': dict(Counter(k['kind'] or 'normal' for r in rows for k in r['dep_kinds'] or [])),
              'metadata_sha256': hashlib.sha256(metadata_raw).hexdigest(),
              'metadata_command': 'cargo metadata --locked --format-version 1 (no --filter-platform)',
              'old_image_pair_verified': False, 'runtime_changed': False, 'direct_accuracy': None,
              'limitation': 'Unfiltered metadata may include other target platforms; edge kinds do not prove build activation'}
    atomic_json(ROOT / 'docs/rust-fd-scopes-v1.json', report)
    print(json.dumps({k: v for k, v in report.items() if k != 'rows'}))


if __name__ == '__main__':
    main()

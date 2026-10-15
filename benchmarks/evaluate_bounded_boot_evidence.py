"""Post-analysis metrics for the disclosed bounded Boot candidate, never input."""
import hashlib
import json

from compare_java_js import all_components, coord
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    output = ROOT / 'benchmarks/results/bounded-boot-evidence-v2'
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve completed evaluation')
    run = json.loads((output / 'report.json').read_bytes())
    assert run['three_views_schema_valid']
    pair = ROOT / 'benchmarks/references/paired-spring-petclinic-v1'
    receipt = json.loads((pair / 'receipt.json').read_bytes())
    for name, expected in receipt['reference_hashes'].items():
        assert hashlib.sha256((pair / name).read_bytes()).hexdigest() == expected
    labels = json.loads((ROOT / 'benchmarks/results/boot-packaging-labels-v3/report.json').read_bytes())
    expected = set(labels['packaged'])
    owner = coord(json.loads((pair / 'sbom.json').read_bytes())['metadata']['component'])
    actual = {coord(c) for c in all_components(json.loads((output / 'final.cdx.json').read_bytes()))
              if coord(c) and any(p.get('name', '').startswith('syft:location:')
                                  and p.get('name', '').endswith(':path')
                                  and p.get('value', '').startswith('/application/')
                                  for p in c.get('properties', []))} - {owner}
    exact = metrics(actual, expected)
    assert exact == run['candidate_final_components']
    identities = {purl.rsplit('@', 1)[0] for purl in actual}
    matched_identity = {purl for purl in expected if purl.rsplit('@', 1)[0] in identities}
    direct = set(labels['root_direct_build'])
    atomic_json(output / 'evaluation.json', {
        'project': labels['project'], 'commit': labels['commit'], 'partition': 'disclosed_development',
        'runtime_changed': False, 'component_exact_micro': exact, 'component_exact_macro': exact,
        'component_count_delta': len(actual) - len(expected),
        'version_accuracy_matched_identity': len(actual & expected) / len(matched_identity) if matched_identity else None,
        'exact_version_coverage': len(actual & expected) / len(expected),
        'known_build_direct': metrics(set(), direct), 'direct_unknown_charged_fn': len(direct),
        'direct_scope': 'Root build compile/runtime declarations, not only packaged subset; no Java owner predictor integrated',
        'unknown_packaging_labels': len(labels['unknown_packaged']),
        'reference_hashes_verified': True,
        'acceptance': False, 'reason': 'Component identity/version precision and recall below90%; no direct integration or independent control',
        'performance': {'seconds': run['elapsed_seconds'], 'peak_rss_bytes': None,
                        'disk_and_index_counters': run['candidate_readers']},
        'limitation': 'One development Boot project, macro=micro here; neither language-wide nor production metrics'})
    print(json.dumps({'components': exact, 'direct_unmatched': len(direct), 'acceptance': False}))


if __name__ == '__main__':
    main()

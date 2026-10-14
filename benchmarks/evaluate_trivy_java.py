"""Evaluate owner-specific Trivy source graph against immutable build references."""
import json
import xml.etree.ElementTree as ET

from java_local_parent import NS
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json


def coordinates(component):
    purl = component.get('purl', '')
    if not purl.startswith('pkg:maven/') or '@' not in purl:
        return None
    package, version = purl.removeprefix('pkg:maven/').split('@', 1)
    group, name = package.rsplit('/', 1)
    return group, name, version.split('?')[0]


def owner_edges(bom, owner):
    matches = [c for c in bom.get('components', []) if coordinates(c) == owner]
    if len(matches) != 1:
        raise ValueError('Owner missing or ambiguous')
    edges = [d for d in bom.get('dependencies', []) if d['ref'] == matches[0]['bom-ref']]
    if len(edges) != 1:
        raise ValueError('Owner graph missing or ambiguous')
    by_ref = {c['bom-ref']: c for c in bom['components']}
    return {coordinates(by_ref[r]) for r in edges[0].get('dependsOn', [])}


def main():
    work = ROOT / 'benchmarks/references/trivy-java-source-v1'
    rows = []
    for name, module in [('gson', 'gson/pom.xml'), ('commons-text', 'pom.xml')]:
        source = ROOT / 'benchmarks/.work' / ('paired-' + name + '-v1') / 'src'
        raw = (source / module).read_bytes()
        root = ET.fromstring(raw)
        owner = tuple(root.findtext('m:' + k, namespaces=NS) or root.findtext('m:parent/m:' + k, namespaces=NS)
                      for k in ('groupId', 'artifactId', 'version'))
        result = json.loads((work / (name + '.cdx.json')).read_bytes())
        actual = owner_edges(result, owner)
        out = ROOT / 'benchmarks/references' / ('paired-' + name + '-v1')
        receipt = json.loads((out / 'receipt.json').read_bytes())
        if sha(source / module) != receipt['reference_hashes']['pom.xml'] or sha(out / 'sbom.json') != receipt['reference_hashes']['sbom.json']:
            raise ValueError('Evidence changed')
        reference = json.loads((out / 'sbom.json').read_bytes())
        refs = root_dependencies(reference)
        expected = {coordinates(c) for c in reference['components'] if c['bom-ref'] in refs}
        rows.append({'project': name, 'owner': owner, 'predicted': sorted(actual), 'reference': sorted(expected),
                     'tp': len(actual & expected), 'fp': len(actual - expected), 'fn': len(expected - actual),
                     'sbom_sha256': sha(work / (name + '.cdx.json')), 'reference_sha256': sha(out / 'sbom.json')})
    synthetic = []
    for name, runtime_expected in [('inherited', False), ('override', True), ('profile', False)]:
        bom = json.loads((work / (name + '.cdx.json')).read_bytes())
        actual = owner_edges(bom, ('fixture', 'child', '1'))
        synthetic.append({'case': name, 'runtime_candidate_present': bool(actual),
                          'matches_selected_build_runtime_scope': bool(actual) == runtime_expected,
                          'profile_activation_proven': False, 'sbom_sha256': sha(work / (name + '.cdx.json'))})
    tp, fp, fn = (sum(r[k] for r in rows) for k in ('tp', 'fp', 'fn'))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    report = {'experiment': 'R34', 'version': 'Trivy0.75.0', 'mode': 'source POM, Maven metadata network allowed, no vulnerability scan',
              'rows': rows, 'synthetic': synthetic, 'tp': sum(r['tp'] for r in rows),
              'fp': sum(r['fp'] for r in rows), 'fn': sum(r['fn'] for r in rows),
              'runtime_changed': False, 'holdout_read': False, 'precision': precision, 'recall': recall, 'f1': f1,
              'limitation': 'Two positive development edges. Profile exclusion may follow inactive provided scope; not proof of activation.'}
    atomic_json(ROOT / 'docs/trivy-java-source-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

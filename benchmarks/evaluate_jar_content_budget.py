"""Post-prediction evaluator for the development Javalin budget experiment."""
import hashlib
import json

from compare_java_js import all_components, coord
from http_integration import command
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    pair = ROOT/'benchmarks/references/paired-javalin-reactor-v1'
    analysis = ROOT/'benchmarks/.work/paired-javalin-reactor-v1/analysis-metadata-archive-v1'
    final = json.loads((analysis/'final.cdx.json').read_bytes())
    receipt = json.loads((pair/'receipt.json').read_bytes())
    for relative, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((pair/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Immutable reference changed')
    provenance = json.loads((analysis/'provenance.json').read_bytes())
    if provenance['image']['image_config_digest'] != receipt['image_binding']['config_digest']:
        raise ValueError('Candidate image binding differs')
    source = analysis.parent/'src'
    if (command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != receipt['commit']
            or command(['git', '-C', str(source), 'status', '--porcelain'])):
        raise ValueError('Candidate source commit or tree differs')
    labels = json.loads((pair/'module-labels.json').read_bytes())
    rows = []
    for label in labels:
        if not label['image_prefix']:
            continue
        reference = json.loads((pair/'modules'/label['path']/'sbom.json').read_bytes())
        owner = coord(reference['metadata']['component'])
        expected = {coord(component) for component in all_components(reference) if coord(component)} - {owner}
        predicted = {coord(component) for component in all_components(final) if coord(component) and any(
            prop.get('name', '').startswith('syft:location:') and prop.get('name', '').endswith(':path')
            and prop.get('value', '').startswith(label['image_prefix']) for prop in component.get('properties', []))} - {owner}
        native = json.loads((pair/'modules'/label['path']/'dependency-tree.json').read_bytes())
        pending = list(native.get('children', []))
        native_components = set()
        for node in pending:
            native_components.add('pkg:maven/'+node['groupId']+'/'+node['artifactId']+'@'+node['version'])
            pending.extend(node.get('children', []))
        row = {'owner': label['owner'], 'path': label['path'], 'components': metrics(predicted, expected),
               'missing': sorted(expected-predicted), 'extra': sorted(predicted-expected),
               'direct_status': 'UNKNOWN', 'known_direct_unmatched': len(label['direct']),
               'native_runtime_components': len(native_components), 'build_reference_components': len(expected)}
        if native_components != expected:
            row['raw_build_reference_delta'] = row['components']
            row['components'] = None
            row['scope_status'] = 'UNKNOWN_NATIVE_CDX_TRANSITIVE_MISMATCH'
            row['cdx_not_in_native_runtime'] = sorted(expected-native_components)
            row['native_runtime_not_in_cdx'] = sorted(native_components-expected)
        else:
            row['scope_status'] = 'NATIVE_CDX_AGREEMENT'
        rows.append(row)
    atomic_json(ROOT/'benchmarks/results/jar-content-budget-v1/evaluation-scoped-v2.json', {
        'development_only': True, 'source_clean_and_image_binding_verified': True, 'scope': 'Per shipped module copied runtime dependency libraries, own module excluded; includes optional declarations',
        'rows': rows, 'direct_classifier_changed': False, 'known_direct_unmatched': sum(row['known_direct_unmatched'] for row in rows),
        'limitation': 'Fixture module prefixes and native/CDX scope used only after prediction; metadata-only/resource dependencies may not meet current class-payload evidence policy. No runtime reachability assertion; not independent acceptance.'})
    print(json.dumps({'owners': len(rows), 'tp': sum(row['components']['tp'] for row in rows if row['components']),
                      'fp': sum(row['components']['fp'] for row in rows if row['components']), 'fn': sum(row['components']['fn'] for row in rows if row['components'])}))


if __name__ == '__main__':
    main()

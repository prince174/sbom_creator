"""Post-analysis image-only Trivy comparison; reference never passed to scanner."""
import hashlib
import json

from compare_java_js import all_components, coord
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    result = ROOT/'benchmarks/results/trivy-reactor-image-v3'
    run = json.loads((result/'run.json').read_bytes())
    if run['exit_code'] != 0:
        raise ValueError('Scan failed')
    document = json.loads((result/'sbom.json').read_bytes())
    registry = Registry()
    schemas = ROOT/'benchmarks/references/trivy-java-source-v1/schemas'
    for path in schemas.glob('*.json'):
        schema = json.loads(path.read_bytes())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    Draft7Validator(json.loads((schemas/'bom-1.7.schema.json').read_bytes()), registry=registry).validate(document)
    pair = ROOT/'benchmarks/references/paired-javalin-reactor-v1'
    receipt = json.loads((pair/'receipt.json').read_bytes())
    for relative, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((pair/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Immutable reference changed')
    image_id = [p['value'] for p in document['metadata']['component']['properties'] if p['name'] == 'aquasecurity:trivy:ImageID']
    if image_id != [receipt['image_binding']['config_digest']]:
        raise ValueError('Trivy image binding differs')
    rows = []
    for label in json.loads((pair/'module-labels.json').read_bytes()):
        if not label['image_prefix']:
            continue
        reference = json.loads((pair/'modules'/label['path']/'sbom.json').read_bytes())
        owner = coord(reference['metadata']['component'])
        expected = {coord(component) for component in all_components(reference) if coord(component)} - {owner}
        predicted = {coord(component) for component in all_components(document) if coord(component) and any(
            prop.get('name') == 'aquasecurity:trivy:FilePath' and ('/'+prop.get('value', '').lstrip('/')).startswith(label['image_prefix'])
            for prop in component.get('properties', []))} - {owner}
        native = json.loads((pair/'modules'/label['path']/'dependency-tree.json').read_bytes())
        pending = list(native.get('children', []))
        native_components = set()
        for node in pending:
            native_components.add('pkg:maven/'+node['groupId']+'/'+node['artifactId']+'@'+node['version'])
            pending.extend(node.get('children', []))
        row = {'owner': label['owner'], 'path': label['path'], 'components': metrics(predicted, expected),
               'missing': sorted(expected-predicted), 'extra': sorted(predicted-expected),
               'direct_status': 'UNKNOWN_IMAGE_INVENTORY_NOT_DIRECT_GRAPH', 'known_direct_unmatched': len(label['direct']),
               'native_runtime_components': len(native_components), 'build_reference_components': len(expected)}
        if native_components != expected:
            row['raw_build_reference_delta'] = row['components']
            row['components'] = None
            row['scope_status'] = 'UNKNOWN_NATIVE_CDX_TRANSITIVE_MISMATCH'
        else:
            row['scope_status'] = 'NATIVE_CDX_AGREEMENT'
        rows.append(row)
    scored = [row for row in rows if row['components'] is not None]
    tp, fp, fn = (sum(row['components'][key] for row in scored) for key in ('tp', 'fp', 'fn'))
    report = {'tool': 'Trivy0.75.0', 'mode': run['mode'], 'development_only': True,
              'schema_valid': True, 'image_binding_verified': True, 'rows': rows,
              'aggregate_agreeing_scope': {'owners': len(scored), 'tp': tp, 'fp': fp, 'fn': fn,
                  'precision': tp/(tp+fp) if tp+fp else None, 'recall': tp/(tp+fn) if tp+fn else None},
              'known_direct_unmatched': sum(row['known_direct_unmatched'] for row in rows),
              'scope_unknown_owners': len(rows)-len(scored), 'runtime_changed': False,
              'limitation': 'Same real image/module prefixes and scope as Syft R89. Inventory is not direct dependencies or payload execution proof. No source resolver, no project execution, no lockfiles, no integration or independent acceptance.'}
    atomic_json(result/'evaluation.json', report)
    print(json.dumps(report['aggregate_agreeing_scope']))


if __name__ == '__main__':
    main()

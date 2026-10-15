"""Evaluate Boot image Trivy output after prediction using packaging labels."""
import hashlib
import json

from compare_java_js import all_components, coord
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    result = ROOT/'benchmarks/results/trivy-boot-image-v1'
    if json.loads((result/'run.json').read_bytes())['exit_code'] != 0:
        raise ValueError('Scan failed')
    document = json.loads((result/'sbom.json').read_bytes())
    registry = Registry()
    schemas = ROOT/'benchmarks/references/trivy-java-source-v1/schemas'
    for path in schemas.glob('*.json'):
        schema = json.loads(path.read_bytes())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    Draft7Validator(json.loads((schemas/'bom-1.7.schema.json').read_bytes()), registry=registry).validate(document)
    pair = ROOT/'benchmarks/references/paired-spring-petclinic-v1'
    receipt = json.loads((pair/'receipt.json').read_bytes())
    for relative, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((pair/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Immutable reference changed')
    image_id = [p['value'] for p in document['metadata']['component']['properties'] if p['name'] == 'aquasecurity:trivy:ImageID']
    if image_id != [receipt['image_binding']['config_digest']]:
        raise ValueError('Trivy image binding differs')
    labels = json.loads((ROOT/'benchmarks/results/boot-packaging-labels-v3/report.json').read_bytes())
    if labels['commit'] != receipt['commit']:
        raise ValueError('Packaging label commit differs')
    reference = json.loads((pair/'sbom.json').read_bytes())
    owner = coord(reference['metadata']['component'])
    predicted = {coord(component) for component in all_components(document) if coord(component) and any(
        prop.get('name') == 'aquasecurity:trivy:FilePath' and prop.get('value', '').lstrip('/').startswith('application/')
        for prop in component.get('properties', []))} - {owner}
    expected = set(labels['packaged'])
    atomic_json(result/'evaluation.json', {'development_only': True, 'schema_valid': True, 'image_binding_verified': True,
        'components_conservative_extra_as_fp': metrics(predicted, expected), 'missing': sorted(expected-predicted),
        'extra': sorted(predicted-expected), 'scope': 'Hash-bound packaged dependency libraries; application owner excluded',
        'packaging_unknown_artifacts': labels['unknown_packaged'], 'build_only_exclusions': sorted(labels['resolved_not_packaged']),
        'known_build_direct_unmatched': len(labels['root_direct_build']), 'direct_status': 'UNKNOWN_IMAGE_INVENTORY_NOT_DIRECT_GRAPH',
        'limitation': 'jarmode-tools packaging artifact remains UNKNOWN, conservatively charged as FP for numeric lower bound. Hibernate group and version discrepancies retained. Oracle only post-analysis. No independent acceptance or runtime integration.'})
    print(json.dumps(metrics(predicted, expected)))


if __name__ == '__main__':
    main()

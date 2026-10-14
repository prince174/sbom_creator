import json
import xml.etree.ElementTree as ET

from evaluate_trivy_java import owner_edges
from java_local_management import project
from java_local_parent import NS
from jsonschema import Draft7Validator
from paired_express import root_dependencies, sha
from referencing import Registry, Resource
from run import ROOT
from trivy_profile_counterexample import OUT

from sbom_creator.validation import validate_cyclonedx


def main():
    receipt = json.loads((OUT / 'receipt.json').read_bytes())
    for name, digest in receipt['hashes'].items():
        if sha(OUT / name) != digest:
            raise ValueError('Evidence changed')
    registry = Registry()
    schemas = ROOT / 'benchmarks/references/trivy-java-source-v1/schemas'
    for path in schemas.glob('*.json'):
        schema = json.loads(path.read_bytes())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    bom = json.loads((OUT / 'trivy.cdx.json').read_bytes())
    Draft7Validator(json.loads((schemas / 'bom-1.7.schema.json').read_bytes()), registry=registry).validate(bom)
    actual = owner_edges(bom, ('fixture', 'profile-switch', '1'))
    reference = json.loads((OUT / 'sbom.json').read_bytes())
    validate_cyclonedx(reference)
    if root_dependencies(reference) or len(actual) != 1:
        raise ValueError('Expected counterexample absent')
    effective = ET.fromstring((OUT / 'effective-pom.xml').read_bytes())
    if [d.findtext('m:scope', 'compile', NS) for d in effective.findall('m:dependencies/m:dependency', NS)] != ['test']:
        raise ValueError('Scope differs')
    if project({'pom.xml': (OUT / 'source/pom.xml').read_bytes()}, 'pom.xml')['status'] != 'UNKNOWN':
        raise ValueError('J1 must abstain')
    print('Hashes, Trivy1.7/CDX1.6 schemas, build test scope, extra edge and J1 UNKNOWN verified')


if __name__ == '__main__':
    main()

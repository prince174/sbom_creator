"""Revalidate immutable synthetic build evidence without rebuilding."""
import json
import xml.etree.ElementTree as ET

from java_local_management import project
from java_local_parent import NS
from maven_scope_fixture import OUT
from paired_express import root_dependencies, sha

from sbom_creator.validation import validate_cyclonedx


def main():
    receipt = json.loads((OUT / 'receipt.json').read_bytes())
    for name, digest in receipt['hashes'].items():
        if sha(OUT / name) != digest:
            raise ValueError('Evidence changed: ' + name)
    for case, scope in (('inherited', 'provided'), ('override', 'runtime'), ('profile', 'test')):
        folder = OUT / case
        prediction = project({p: (folder / 'source' / p).read_bytes() for p in ('pom.xml', 'child/pom.xml')}, 'child/pom.xml')
        effective = ET.fromstring((folder / 'effective-pom.xml').read_bytes())
        deps = effective.findall('m:dependencies/m:dependency', NS)
        if len(deps) != 1 or deps[0].findtext('m:scope', namespaces=NS) != scope:
            raise ValueError('Build scope mismatch')
        if case == 'profile':
            if prediction['status'] != 'UNKNOWN':
                raise ValueError('Profile must remain unknown')
        elif len(prediction['rows']) != 1 or prediction['rows'][0]['scope'] != scope:
            raise ValueError('Prediction mismatch')
        bom = json.loads((folder / 'sbom.json').read_bytes())
        validate_cyclonedx(bom)
        direct = root_dependencies(bom)
        coordinates = [(c.get('group'), c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in direct]
        if coordinates != [('org.apache.commons', 'commons-lang3', '3.17.0')]:
            raise ValueError('CycloneDX direct coordinates mismatch')
    print('3 build references validated; 2 matching static scopes, 1 profile UNKNOWN')


if __name__ == '__main__':
    main()

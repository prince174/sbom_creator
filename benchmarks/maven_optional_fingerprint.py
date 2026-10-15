"""Experimental optional-declaration + image JAR SHA256 evidence, never oracle-fed."""
import hashlib
import json
import re
import tarfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from compare_java_js import all_components, coord, graph
from run import ROOT, atomic_json
from score_project_components import metrics

NS = {'m': 'http://maven.apache.org/POM/4.0.0'}


def optional_declarations(raw):
    root = ET.fromstring(raw)
    properties = {p.tag.split('}')[-1]: p.text for p in root.findall('m:properties/*', NS)}
    rows = []
    for dep in root.findall('m:dependencies/m:dependency', NS):
        if dep.findtext('m:optional', default='false', namespaces=NS) != 'true':
            continue
        if dep.findtext('m:scope', default='compile', namespaces=NS) not in ('compile', 'runtime'):
            continue
        values = [dep.findtext('m:' + k, namespaces=NS) for k in ('groupId', 'artifactId', 'version')]
        for i, value in enumerate(values):
            if value and re.fullmatch(r'\$\{[^}]+\}', value):
                values[i] = properties.get(value[2:-1])
        if all(v and re.fullmatch(r'[A-Za-z0-9_.+-]+', v) and v not in ('.', '..') for v in values):
            rows.append(tuple(values))
    return rows


def main():
    directory = ROOT / 'benchmarks/results/java-js-twenty-v1'
    rows = []
    for receipt_path in sorted((ROOT / 'benchmarks/references').glob('paired-*/receipt.json')):
        receipt = json.loads(receipt_path.read_bytes())
        project = receipt.get('project', '')
        if not project.startswith('java-'):
            continue
        work = ROOT / 'benchmarks/.work' / receipt_path.parent.name
        source = work / 'src' / ('gson/pom.xml' if project == 'java-gson' else 'slf4j-api/pom.xml' if project == 'java-slf4j' else 'pom.xml')
        candidates = optional_declarations(source.read_bytes())
        image = json.loads((work / 'analysis/image.syft.json').read_bytes())
        image_claims = {coord(a) for a in image['artifacts'] if coord(a)}
        accepted, evidence = set(), []
        with tarfile.open(work / 'runtime-app.tar') as archive:
            for group, name, version in candidates:
                coordinate = 'pkg:maven/' + group + '/' + name + '@' + version
                members = [m for m in archive.getmembers() if m.isfile() and m.name.rsplit('/', 1)[-1] == name + '-' + version + '.jar']
                if len(members) != 1 or members[0].size > 32 * 1024 * 1024:
                    continue
                if coordinate in image_claims:
                    accepted.add(coordinate)
                    evidence.append({'name': name, 'status': 'MATCHED_IMAGE_DECLARATION',
                                     'evidence': 'explicit_optional_declaration_and_existing_image_coordinate'})
                    continue
                payload = archive.extractfile(members[0]).read()
                digest = hashlib.sha256(payload).hexdigest()
                url = 'https://repo.maven.apache.org/maven2/' + group.replace('.', '/') + '/' + name + '/' + version + '/' + name + '-' + version + '.jar.sha256'
                try:
                    with urllib.request.urlopen(url, timeout=10) as response:
                        expected_digest = response.read(129).decode('ascii').strip().lower()
                except (OSError, UnicodeError):
                    evidence.append({'name': name, 'status': 'UNKNOWN', 'reason': 'repository_fingerprint_unavailable'})
                    continue
                if re.fullmatch(r'[a-f0-9]{64}', expected_digest) and digest == expected_digest:
                    accepted.add(coordinate)
                    evidence.append({'name': name, 'status': 'MATCHED', 'sha256': digest, 'url': url})
                else:
                    evidence.append({'name': name, 'status': 'UNKNOWN', 'reason': 'fingerprint_mismatch_or_invalid'})
        # Reference read only after source+image+repository prediction.
        reference = json.loads((receipt_path.parent / 'sbom.json').read_bytes())
        owner = coord(reference['metadata']['component'])
        document = json.loads((directory / (project + '-trivy.json')).read_bytes())
        direct = graph(document, owner)
        components = {coord(c) for c in all_components(document) if coord(c)} - {owner}
        expected_components = {coord(c) for c in all_components(reference) if coord(c)} - {owner}
        rows.append({'project': project, 'fingerprint_evidence': evidence,
                     'components': metrics(components | accepted, expected_components),
                     'direct': metrics(direct | accepted, graph(reference, owner)) if direct is not None else None})
    atomic_json(ROOT / 'docs/maven-optional-fingerprint-v1.json', {'rows': rows, 'runtime_changed': False,
                'limitation': 'Exploratory known fixtures, repository checksum trust, optional explicit local declarations only; no production adoption or independent-control claim'})
    print(json.dumps(rows))


if __name__ == '__main__':
    main()

"""Build a default-runtime / activated-test fixture and compare source Trivy."""
import json
import shutil
import xml.etree.ElementTree as ET

import paired_express as shared
from evaluate_trivy_java import owner_edges
from java_local_management import project
from java_local_parent import NS
from maven_scope_fixture import BASE, dependency, pom
from run import ROOT, atomic_json, run_command

from sbom_creator.validation import validate_cyclonedx

WORK = ROOT / 'benchmarks/.work/trivy-profile-r35'
OUT = ROOT / 'benchmarks/references/trivy-profile-v1'


def main():
    if (OUT / 'receipt.json').exists():
        raise FileExistsError('Immutable reference exists')
    (WORK / 'source/src/main/java').mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    dep = dependency('<version>3.17.0</version>')
    raw = pom('<groupId>fixture</groupId><artifactId>profile-switch</artifactId><version>1</version>'
              '<properties><maven.compiler.source>8</maven.compiler.source><maven.compiler.target>8</maven.compiler.target></properties>'
              '<dependencies>' + dep + '</dependencies><profiles><profile><id>switch</id><dependencies>'
              + dependency('<version>3.17.0</version><scope>test</scope>') + '</dependencies></profile></profiles>')
    (WORK / 'source/pom.xml').write_text(raw, encoding='utf-8')
    (WORK / 'source/src/main/java/App.java').write_text('public class App {}\n', encoding='utf-8')
    j1 = project({'pom.xml': raw.encode()}, 'pom.xml')
    trivy = ROOT / 'benchmarks/.work/trivy-r34/trivy.exe'
    run_command([str(trivy), 'fs', '--format', 'cyclonedx', '--skip-db-update', '--skip-java-db-update',
                 '--disable-telemetry', '--timeout', '3m', '--cache-dir', str(WORK / 'cache'),
                 '--output', str(WORK / 'trivy.cdx.json'), str(WORK / 'source')], WORK / 'trivy.log')
    actual = owner_edges(json.loads((WORK / 'trivy.cdx.json').read_bytes()), ('fixture', 'profile-switch', '1'))
    recipe = (f'FROM {BASE}\nENV MAVEN_OPTS=-XX:ActiveProcessorCount=2\nWORKDIR /fixture\nCOPY source/ /fixture/\n'
              'RUN --mount=type=cache,target=/root/.m2 mkdir /reference && mvn -B -ntp -Pswitch package '
              'org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DincludeTestScope=false '
              'org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/effective-pom.xml '
              '&& cp target/bom.json /reference/sbom.json\n'
              'RUN mvn --version > /reference/maven-version.txt\n')
    (WORK / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (WORK / '.dockerignore').write_text('**\n!Dockerfile\n!source/\n!source/**\n', encoding='utf-8')
    run_command(['docker', 'build', '--platform', 'linux/amd64', '--iidfile', str(WORK / 'build.id'), str(WORK)], WORK / 'build.log', timeout=1200)
    shared.WORK = WORK
    image = (WORK / 'build.id').read_text().strip()
    shared.export_from_image(image, [('/reference/.', OUT, False)], 'reference')
    effective = ET.fromstring((OUT / 'effective-pom.xml').read_bytes())
    scopes = [d.findtext('m:scope', 'compile', NS) for d in effective.findall('m:dependencies/m:dependency', NS)]
    reference = json.loads((OUT / 'sbom.json').read_bytes())
    validate_cyclonedx(reference)
    expected_refs = shared.root_dependencies(reference)
    if scopes != ['test'] or expected_refs:
        raise ValueError('Unexpected selected build scope/reference')
    for name in ('Dockerfile', 'trivy.cdx.json'):
        shutil.copyfile(WORK / name, OUT / name)
    shutil.copytree(WORK / 'source', OUT / 'source', dirs_exist_ok=True)
    report = {'experiment': 'R35', 'synthetic': True, 'profile': '-Pswitch', 'build_scope': scopes,
              'reference_runtime_edges': 0, 'trivy_predicted_edges': sorted(actual),
              'runtime_false_positive_edges': len(actual), 'j1': j1,
              'runtime_changed': False, 'direct_precision': None, 'direct_recall': None,
              'reason': 'Targeted profile counterexample, not representative accuracy; no image replay'}
    atomic_json(OUT / 'results.json', report)
    atomic_json(OUT / 'receipt.json', {'build_image': image, 'trivy_binary_sha256': shared.sha(trivy),
                'hashes': {p.relative_to(OUT).as_posix(): shared.sha(p) for p in OUT.rglob('*') if p.is_file()}})
    atomic_json(ROOT / 'docs/trivy-profile-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

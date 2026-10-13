"""External synthetic Maven builds for management/profile counterexamples."""
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET

import paired_express as shared
from java_local_management import project
from java_local_parent import NS
from run import ROOT, atomic_json, run_command

from sbom_creator.validation import validate_cyclonedx

WORK = ROOT / "benchmarks/.work/maven-scope-fixture-v1"
OUT = ROOT / "benchmarks/references/maven-scope-fixture-v1"
BASE = "maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584"


def pom(body):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>' + body + '</project>')


def dependency(scope=""):
    return ('<dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>'
            + scope + '</dependency>')


def main():
    if (OUT / "receipt.json").exists():
        raise FileExistsError("Immutable fixture completed")
    WORK.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    cases = ("inherited", "override", "profile")
    predictions = {}
    for case in cases:
        root = WORK / case
        (root / "child/src/main/java").mkdir(parents=True, exist_ok=True)
        managed = dependency('<version>3.17.0</version><scope>provided</scope>')
        parent = pom('<groupId>fixture</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>'
                     '<dependencyManagement><dependencies>' + managed + '</dependencies></dependencyManagement>')
        extra = '<scope>runtime</scope>' if case == 'override' else ''
        profile = ('<profiles><profile><id>switch</id><dependencies>' + dependency('<scope>test</scope>') +
                   '</dependencies></profile></profiles>') if case == 'profile' else ''
        child = pom('<parent><groupId>fixture</groupId><artifactId>parent</artifactId><version>1</version></parent>'
                    '<artifactId>child</artifactId><properties><maven.compiler.source>8</maven.compiler.source>'
                    '<maven.compiler.target>8</maven.compiler.target></properties><dependencies>' + dependency(extra) + '</dependencies>' + profile)
        (root / 'pom.xml').write_text(parent, encoding='utf-8')
        (root / 'child/pom.xml').write_text(child, encoding='utf-8')
        (root / 'child/src/main/java/App.java').write_text('public class App {}\n', encoding='utf-8')
        predictions[case] = project({'pom.xml': parent.encode(), 'child/pom.xml': child.encode()}, 'child/pom.xml')
    recipe = f'FROM {BASE}\nENV MAVEN_OPTS=-XX:ActiveProcessorCount=2\nWORKDIR /fixture\n'
    for case in cases:
        recipe += f'COPY {case}/ /fixture/{case}/\n'
    recipe += 'RUN mkdir -p /reference\n'
    for case in cases:
        flags = '-Pswitch' if case == 'profile' else ''
        recipe += (f'RUN --mount=type=cache,target=/root/.m2 mkdir /reference/{case} && '
                   f'mvn -B -ntp -f {case}/child/pom.xml {flags} package '
                   'org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DincludeTestScope=true '
                   f'org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/{case}/effective-pom.xml '
                   f'&& cp {case}/child/target/bom.json /reference/{case}/sbom.json\n')
    recipe += 'RUN mvn --version > /reference/maven-version.txt\n'
    (WORK / 'Dockerfile').write_text(recipe, encoding='utf-8')
    run_command(['docker', 'build', '--platform', 'linux/amd64', '--iidfile', str(WORK / 'build.id'), str(WORK)], WORK / 'build.log', timeout=1800)
    shared.WORK = WORK
    identity = (WORK / 'build.id').read_text().strip()
    shared.export_from_image(identity, [('/reference/.', OUT, False)], 'reference')
    results = []
    for case in cases:
        effective = ET.fromstring((OUT / case / 'effective-pom.xml').read_bytes())
        fields = [(d.findtext('m:artifactId', namespaces=NS), d.findtext('m:version', namespaces=NS),
                   d.findtext('m:scope', 'compile', NS)) for d in effective.findall('m:dependencies/m:dependency', NS)]
        bom = json.loads((OUT / case / 'sbom.json').read_bytes())
        validate_cyclonedx(bom)
        refs = shared.root_dependencies(bom)
        direct = [c['purl'] for c in bom['components'] if c['bom-ref'] in refs]
        results.append({'case': case, 'prediction': predictions[case], 'effective_fields': fields,
                        'cyclonedx_direct': direct, 'profile_flags': '-Pswitch' if case == 'profile' else ''})
        for path in ("pom.xml", "child/pom.xml", "child/src/main/java/App.java"):
            destination = OUT / case / 'source' / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(WORK / case / path, destination)
    shutil.copyfile(WORK / 'Dockerfile', OUT / 'Dockerfile')
    report = {'experiment': 'R29', 'synthetic': True, 'runtime_changed': False, 'results': results,
              'image_pair_evaluated': False, 'direct_accuracy': None,
              'reason': 'Build-model counterexamples only; no analyzer image replay'}
    atomic_json(OUT / 'results.json', report)
    atomic_json(OUT / 'receipt.json', {'build_image': identity,
                'harness_base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                'hashes': {p.relative_to(OUT).as_posix(): shared.sha(p) for p in OUT.rglob('*') if p.is_file()}})
    atomic_json(ROOT / 'docs/maven-scope-fixture-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

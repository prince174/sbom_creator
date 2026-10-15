"""Sequential external Maven library build/image pairs; oracle never a scan input."""
import argparse
import base64
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET

import paired_express as shared
from http_integration import command
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

BASE = 'maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584'


def recipe(project):
    artifact = project['expected_package'].split(':')[1]
    version = project['expected_version']
    module = 'slf4j-api' if project['id'] == 'java-slf4j' else '.'
    mvn = ('mvn -B -ntp -f ' + module + '/pom.xml -DskipTests -Dmaven.test.skip=true '
           '-Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true ')
    return (f'FROM {BASE} AS build\nENV MAVEN_OPTS=-XX:ActiveProcessorCount=2\nWORKDIR /src\nCOPY src/ /src/\n'
            'RUN mkdir /reference /application\n'
            'RUN --mount=type=cache,target=/root/.m2 ' + mvn +
            'package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DoutputName=sbom '
            '-DincludeTestScope=false -DincludeProvidedScope=false -DincludeSystemScope=false '
            'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies -DincludeScope=runtime && '
            f'test "$(find {module}/target -maxdepth 1 -name \'*bom*.json\' | wc -l)" = 1 && '
            f'find {module}/target -maxdepth 1 -name \'*bom*.json\' -exec cp {{}} /reference/sbom.json \\; && '
            f'cp {module}/target/{artifact}-{version}.jar /application/ && '
            f'if [ -d {module}/target/dependency ]; then find {module}/target/dependency -name \'*.jar\' -exec cp {{}} /application/ \\; ; fi\n'
            'RUN --mount=type=cache,target=/root/.m2 ' + mvn +
            'org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=/reference/effective-pom.xml && ' + mvn +
            'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -Dscope=runtime -DoutputType=json -DoutputFile=/reference/dependency-tree.json && ' + mvn +
            'org.apache.maven.plugins:maven-help-plugin:3.5.1:active-profiles -Doutput=/reference/active-profiles.txt && '
            'mvn --version > /reference/maven-version.txt && sha256sum /application/*.jar > /reference/jars.sha256\n'
            'FROM scratch AS runtime\nCOPY --from=build /application /application\nUSER 65532:65532\nCMD ["/not-executed-library-artifact-fixture"]\n')


def verify_root(bom, native, effective):
    def gav(node):
        return tuple(node[k] for k in ('groupId', 'artifactId', 'version'))
    root = bom['metadata']['component']
    if (root.get('group'), root['name'], root['version']) != gav(native):
        raise ValueError('Reference root differs from native owner')
    components = {c['bom-ref']: c for c in bom.get('components', [])}
    actual = {(components[r].get('group'), components[r]['name'], components[r]['version']) for r in shared.root_dependencies(bom)}
    expected = {gav(c) for c in native.get('children', [])}
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    model = ET.fromstring(effective)
    declared = {tuple(d.findtext('m:' + k, namespaces=ns) for k in ('groupId', 'artifactId', 'version'))
                for d in model.findall('m:dependencies/m:dependency', ns)
                if d.findtext('m:scope', default='compile', namespaces=ns) in ('compile', 'runtime')}
    if actual != expected or declared != expected:
        raise ValueError('CDX/native/effective root graph differs')
    return {'owner': gav(native), 'direct': sorted(expected), 'scope': 'compile/runtime; excludes test/provided/system',
            'build_execution_of_each_dependency': 'UNKNOWN'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True)
    parser.add_argument('--manifest', default='benchmarks/manifest.json')
    args = parser.parse_args()
    project = next(p for p in json.loads((ROOT / args.manifest).read_bytes())['repositories']
                   if p['id'] == args.project and p['language'] == 'Java')
    name = project['id'].removeprefix('java-')
    work = ROOT / 'benchmarks/.work' / ('paired-' + name + '-v1')
    out = ROOT / 'benchmarks/references' / ('paired-' + name + '-v1')
    if (out / 'receipt.json').exists():
        raise FileExistsError('Immutable pair exists')
    work.mkdir(parents=True, exist_ok=True)
    source = work / 'src'
    if not source.exists():
        run_command(['git', 'clone', '--no-hardlinks', '--no-checkout', str(ROOT / 'benchmarks/.work' / project['id'] / 'src'), str(source)], work / 'clone.log')
        run_command(['git', '-c', 'core.autocrlf=false', 'checkout', '--detach', project['commit']], work / 'checkout.log', cwd=source)
    if command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != project['commit'] or command(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('Source commit or cleanliness differs')
    text = recipe(project)
    if (work / 'Dockerfile').exists() and (work / 'Dockerfile').read_text() != text:
        raise ValueError('Existing checkpoint recipe changed')
    (work / 'Dockerfile').write_text(text, encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!src/\n!src/**\nsrc/.git/\n', encoding='utf-8')
    shared.WORK = work
    out.mkdir(parents=True, exist_ok=True)
    for stage in ('build', 'runtime'):
        if not (work / (stage + '.id')).exists():
            run_command(['docker', 'build', '--platform=linux/amd64', '--target', stage, '--iidfile', str(work / (stage + '.id')), str(work)], work / (stage + '.log'), timeout=1800)
        exports = [('/application', work / (stage + '-app.tar'), True)]
        if stage == 'build':
            exports.append(('/reference/.', out, False))
        shared.export_from_image((work / (stage + '.id')).read_text().strip(), exports, stage)
    tree = shared.application_tree(work / 'runtime-app.tar')
    if not tree or tree != shared.application_tree(work / 'build-app.tar'):
        raise ValueError('Application trees differ')
    bom = json.loads((out / 'sbom.json').read_bytes())
    validate_cyclonedx(bom)
    labels = verify_root(bom, json.loads((out / 'dependency-tree.json').read_bytes()), (out / 'effective-pom.xml').read_bytes())
    runtime = (work / 'runtime.id').read_text().strip()
    archive = work / 'image.tar'
    if not archive.exists():
        run_command(['docker', 'image', 'save', '-o', str(archive), runtime], work / 'save.log', timeout=300)
    binding = shared.archive_binding(archive, runtime)
    analysis = work / 'analysis'
    if not (analysis / 'summary.json').exists():
        analyze_local(source, 'docker.io/sbom-creator-benchmark/paired-' + name + ':v1', analysis,
                      Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(archive)))
    image = json.loads((analysis / 'image.syft.json').read_bytes())
    if 'sha256:' + hashlib.sha256(base64.b64decode(image['source']['metadata']['config'], validate=True)).hexdigest() != binding['config_digest']:
        raise ValueError('Scanned image differs')
    for view in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis / (view + '.cdx.json')).read_bytes()))
    shutil.copyfile(work / 'Dockerfile', out / 'Dockerfile')
    shutil.copyfile(source / ('slf4j-api/pom.xml' if name == 'slf4j' else 'pom.xml'), out / 'pom.xml')
    atomic_json(out / 'application-tree.json', tree)
    atomic_json(out / 'direct-labels.json', labels)
    atomic_json(out / 'receipt.json', {'project': project['id'], 'commit': project['commit'],
        'image_binding': binding, 'artifact_tree_equal': True, 'reference_only_for_evaluation': True,
        'reference_hashes': {p.name: shared.sha(p) for p in out.iterdir() if p.is_file() and p.name != 'receipt.json'},
        'outputs': {p.name: shared.sha(p) for p in analysis.iterdir() if p.is_file()},
        'summary': json.loads((analysis / 'summary.json').read_bytes()), 'direct_accuracy': None,
        'limitation': 'Library artifact image, no JRE/application execution; direct classifier not inferred from inventory'})
    print(json.dumps({'project': project['id'], 'paired': True, 'direct_edges': len(labels['direct'])}))


if __name__ == '__main__':
    main()

"""Complete the existing external Dropwizard build; never start a duplicate."""
import hashlib
import json
import shutil
import tarfile
from pathlib import PurePosixPath

from http_integration import command
from paired_express import application_tree, archive_binding, export_from_image
from paired_java import verify_root
from run import ROOT, atomic_json, run_command

from sbom_creator.validation import validate_cyclonedx


def main(project=None, namespace='paired-dropwizard-reactor-v1'):
    project = project or {'id': 'java-dropwizard', 'commit': '14b738b8ca8a52cb245f855cee0dcc68327f1d72',
                          'partition': 'holdout', 'expected_package': 'io.dropwizard:dropwizard-project'}
    if namespace not in ('paired-dropwizard-reactor-v1', 'paired-petclinic-microservices-r104', 'paired-vertx-web-r104'):
        raise ValueError('Unreviewed namespace')
    work = ROOT / 'benchmarks/.work' / namespace
    output = ROOT / 'benchmarks/references' / namespace
    if (output / 'receipt.json').exists():
        raise FileExistsError('Immutable pair already complete')
    if not (work / 'build.id').exists():
        raise FileNotFoundError('Existing build not finished; do not duplicate it')
    source = work / 'src'
    if (command(['git', '-C', str(source), 'rev-parse', 'HEAD']) !=
            project['commit'] or
            command(['git', '-C', str(source), 'status', '--porcelain'])):
        raise ValueError('Source commit or cleanliness differs')
    plan = json.loads((work / 'plan.json').read_bytes())
    if not (work / 'runtime.id').exists():
        run_command(['docker', 'build', '--platform=linux/amd64', '--target', 'runtime',
                     '--iidfile', str(work / 'runtime.id'), str(work)], work / 'runtime.log', timeout=2400)
    for stage in ('build', 'runtime'):
        exports = []
        if not (work / (stage + '-app.tar')).exists():
            exports.append(('/application', work / (stage + '-app.tar'), True))
        if stage == 'build' and not (work / 'reference.tar').exists():
            exports.append(('/reference', work / 'reference.tar', True))
        if exports:
            export_from_image((work / (stage + '.id')).read_text().strip(), exports, stage)
    output.mkdir(exist_ok=True)
    with tarfile.open(work / 'reference.tar') as archive:
        for member in archive:
            name = member.name.removeprefix('reference/')
            if not member.isfile():
                continue
            if (PurePosixPath(name).is_absolute() or '\\' in name or ':' in name or
                    any(part in ('', '.', '..') for part in name.split('/')) or member.size > 16 * 1024 * 1024):
                raise ValueError('Unsafe reference export')
            target = output / name
            if target.exists():
                if target.read_bytes() != archive.extractfile(member).read():
                    raise ValueError('Previously exported reference differs')
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
    tree = application_tree(work / 'runtime-app.tar')
    if tree != application_tree(work / 'build-app.tar'):
        raise ValueError('Build and final artifact trees differ')
    by_path = {item['path']: item for item in tree}
    labels = []
    for item in plan['modules']:
        path = item['path']
        folder = 'root' if path == '.' else path
        directory = output / 'modules' / folder
        actual = json.loads((directory / 'module.json').read_bytes())
        if actual['packaging'] != item['packaging']:
            raise ValueError('Effective packaging differs from planned scope')
        bom = json.loads((directory / 'sbom.json').read_bytes())
        validate_cyclonedx(bom)
        native = json.loads((directory / 'dependency-tree.json').read_bytes())
        root = verify_root(bom, native, (directory / 'effective-pom.xml').read_bytes())
        if root['owner'] != (actual['group'], actual['artifact'], actual['version']):
            raise ValueError('Maven effective coordinates differ')
        prefix = '/application/' + folder + '/' if actual['packaging'] == 'jar' else None
        if prefix and by_path[folder + '/' + actual['file']]['sha256'] != actual['sha256']:
            raise ValueError('Primary artifact SHA256 differs')
        qualifiers = [c for c in native.get('children', []) if c.get('classifier') or c.get('type') not in ('jar', None)]
        labels.append({'path': path, **root, 'packaging': actual['packaging'], 'artifact': actual['artifact'],
                       'image_prefix': prefix, 'effective_output': actual,
                       'direct_classifier_or_type_details': qualifiers,
                       'qualifier_evaluation': 'UNKNOWN_REQUIRES_EXACT_PURL_LABELS' if qualifiers else 'PLAIN_JAR_GAV'})
    aggregate = json.loads((output / 'aggregate/sbom.json').read_bytes())
    validate_cyclonedx(aggregate)
    if aggregate['metadata']['component']['name'] != project['expected_package'].split(':')[1]:
        raise ValueError('Aggregate was overwritten by a module BOM')
    shutil.copyfile(output / 'aggregate/sbom.json', output / 'sbom.json')
    atomic_json(output / 'module-labels.json', labels)
    atomic_json(output / 'application-tree.json', tree)
    archive = work / 'image.tar'
    runtime = (work / 'runtime.id').read_text().strip()
    if not archive.exists():
        run_command(['docker', 'image', 'save', '-o', str(archive), runtime], work / 'save.log', timeout=600)
    binding = archive_binding(archive, runtime)
    for name in ('Dockerfile', 'ReactorCollect.java', 'plan.json'):
        shutil.copyfile(work / name, output / name)
    atomic_json(output / 'receipt.json', {
        'project': project['id'], 'commit': project['commit'],
        'partition': project['partition'], 'runtime_kind': 'maven-reactor-artifacts', 'image_binding': binding,
        'artifact_tree_equal': True, 'reference_only_for_evaluation': True,
        'module_count': len(labels), 'shipped_jar_owners': sum(row['image_prefix'] is not None for row in labels),
        'module_direct_edges': sum(len(row['direct']) for row in labels),
        'analysis_status': {'status': 'PENDING_FROZEN_PREDICTION'},
        'reference_hashes': {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in output.rglob('*') if p.is_file() and p.name != 'receipt.json'},
        'limitation': 'Profiles recorded in plan and active-profiles; tests compiled/not executed. Library artifact fixture, not application smoke. Per-module effective/native/CDX GAV agreement; classifier/type-qualified direct edges marked UNKNOWN until exact PURL labelling. Aggregate components are not direct ground truth.'})
    print(json.dumps({'paired': True, 'modules': len(labels), 'shipped': sum(row['image_prefix'] is not None for row in labels)}))


if __name__ == '__main__':
    main()

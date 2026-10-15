"""Compare image-derived npm manifest/lock graphs; references evaluation-only."""
import hashlib
import json
import os
import subprocess
import tarfile

from compare_java_js import NODE, coord, graph
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from run import ROOT, atomic_json

from sbom_creator.validation import validate_cyclonedx


def main():
    out = ROOT / 'benchmarks/results/npm-image-manifests-v1'
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for project, pair in [('koa', 'koa-v1'), ('fastify', 'fastify-v1'), ('hapi', 'hapi-v3')]:
        work = ROOT / 'benchmarks/.work' / ('paired-' + pair)
        target = out / (project + '-input')
        target.mkdir(exist_ok=True)
        # This export is from the verified runtime image, not the build reference.
        with tarfile.open(work / 'runtime-app.tar') as archive:
            for name in ('package.json', 'package-lock.json'):
                members = [m for m in archive.getmembers() if m.name.removeprefix('./') == 'app/' + name]
                if len(members) != 1 or not members[0].isfile() or members[0].size > 16 * 1024 * 1024:
                    raise ValueError('Manifest missing, ambiguous or oversized')
                (target / name).write_bytes(archive.extractfile(members[0]).read())
        for tool in ('trivy', 'cdxgen'):
            output = out / (project + '-' + tool + '.json')
            log = out / (project + '-' + tool + '.log')
            if not log.exists():
                env = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
                env.update(TEMP=str(out), TMP=str(out))
                if tool == 'trivy':
                    args = [str(ROOT / 'benchmarks/.work/trivy-r34/trivy.exe'), 'fs', '--format', 'cyclonedx',
                            '--scanners', 'license', '--skip-db-update', '--skip-java-db-update', '--skip-version-check',
                            '--output', str(output), str(target)]
                else:
                    args = [NODE, '--permission', '--allow-fs-read=*', '--allow-fs-write=' + str(out),
                            str(ROOT / 'benchmarks/.work/cdxgen-r33/bin/cdxgen.js'), '-t', 'js', '--lifecycle', 'pre-build',
                            '--no-install-deps', '--no-recurse', '--spec-version', '1.6', '-o', str(output), str(target)]
                result = subprocess.run(args, capture_output=True, env=env, timeout=120, check=False)
                log.write_bytes(result.stdout + result.stderr)
            reference = json.loads((ROOT / 'benchmarks/references' / ('paired-' + pair) / 'sbom.json').read_bytes())
            owner = coord(reference['metadata']['component'])
            expected = graph(reference, owner)
            row = {'project': project, 'tool': tool, 'mode': 'runtime image root manifest/lock, no project execution',
                   'reference_direct': len(expected), 'status': 'NO_SBOM'}
            if output.exists():
                document = json.loads(output.read_bytes())
                if tool == 'cdxgen':
                    validate_cyclonedx(document)
                else:
                    schemas = ROOT / 'benchmarks/references/trivy-java-source-v1/schemas'
                    registry = Registry()
                    for path in schemas.glob('*.json'):
                        schema = json.loads(path.read_bytes())
                        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
                    Draft7Validator(json.loads((schemas / 'bom-1.7.schema.json').read_bytes()), registry=registry).validate(document)
                row['schema_valid'] = True
                row['input_hashes'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in target.iterdir() if p.is_file()}
                actual = graph(document, owner, npm_lock_wrapper=tool == 'trivy')
                row['status'] = 'GRAPH_UNKNOWN' if actual is None else 'MEASURED'
                if actual is not None:
                    row.update(predicted_direct=len(actual), tp=len(actual & expected), fp=len(actual - expected),
                               fn=len(expected - actual), count_delta=len(actual) - len(expected))
            rows.append(row)
            atomic_json(out / 'summary.json', {'experiment': 'R65', 'rows': rows, 'runtime_changed': False})
    print(json.dumps(rows))


if __name__ == '__main__':
    main()

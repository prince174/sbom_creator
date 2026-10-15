"""Fixed20-pair candidate evaluation; no reference input to scanners."""
import json
import os
import subprocess
import tarfile

from compare_java_js import NODE, all_components, coord, graph
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    out = ROOT / 'benchmarks/results/java-js-twenty-v1'
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    receipts = []
    split = json.loads((ROOT / 'benchmarks/java-js-twenty-split.json').read_bytes())
    selected = set(split['development_projects'])
    for path in sorted((ROOT / 'benchmarks/references').glob('paired-*/receipt.json')):
        receipt = json.loads(path.read_bytes())
        if receipt.get('project') in selected:
            receipts.append((path, receipt))
    if len(receipts) != 20:
        raise ValueError('Expected20 Java/JS pairs')
    for receipt_path, receipt in receipts:
        project = receipt['project']
        js = project.startswith('javascript-')
        work = ROOT / 'benchmarks/.work' / receipt_path.parent.name
        source = work / 'src'
        manifest, production_packages = None, None
        if js:
            source = out / (project + '-input')
            source.mkdir(exist_ok=True)
            with tarfile.open(work / 'runtime-app.tar') as archive:
                for name in ('package.json', 'package-lock.json'):
                    entries = [m for m in archive.getmembers() if m.name.removeprefix('./') == 'app/' + name]
                    if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 16 * 1024 * 1024:
                        raise ValueError('Unsafe or missing image manifest')
                    (source / name).write_bytes(archive.extractfile(entries[0]).read())
            manifest = json.loads((source / 'package.json').read_bytes())
            lock = json.loads((source / 'package-lock.json').read_bytes())
            production_packages = set()
            for path, item in lock.get('packages', {}).items():
                if 'node_modules/' in path and item.get('version') and not item.get('dev') and not item.get('devOptional') and not item.get('link'):
                    name = item.get('name') or path.rsplit('node_modules/', 1)[1]
                    production_packages.add('pkg:npm/' + name + '@' + item['version'])
        target = source / 'gson' if project == 'java-gson' else source / 'slf4j-api' if project == 'java-slf4j' else source
        for tool in ('trivy', 'cdxgen'):
            output, log = out / (project + '-' + tool + '.json'), out / (project + '-' + tool + '.log')
            if not log.exists():
                env = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
                env.update(TEMP=str(out), TMP=str(out))
                if tool == 'trivy':
                    args = [str(ROOT / 'benchmarks/.work/trivy-r34/trivy.exe'), 'fs', '--format', 'cyclonedx',
                            '--scanners', 'license', '--skip-db-update', '--skip-java-db-update', '--skip-version-check',
                            '--output', str(output), str(target)]
                else:
                    args = [NODE, '--permission', '--allow-fs-read=*', '--allow-fs-write=' + str(out),
                            str(ROOT / 'benchmarks/.work/cdxgen-r33/bin/cdxgen.js'), '-t', 'js' if js else 'java',
                            '--lifecycle', 'pre-build', '--no-install-deps', '--no-resolve-class', '--no-recurse',
                            '--spec-version', '1.6', '-o', str(output), str(target)]
                try:
                    result = subprocess.run(args, capture_output=True, env=env, timeout=120, check=False)
                    log.write_bytes(result.stdout + result.stderr)
                except subprocess.TimeoutExpired:
                    log.write_text('TIMEOUT', encoding='utf-8')
            # Oracle access after scanner. All normalization uses input manifests.
            reference = json.loads((receipt_path.parent / 'sbom.json').read_bytes())
            owner = coord(reference['metadata']['component'])
            expected = graph(reference, owner)
            expected_components = {coord(c) for c in all_components(reference) if coord(c)} - {owner}
            row = {'project': project, 'tool': tool, 'status': 'NO_SBOM', 'reference_direct': len(expected),
                   'reference_components': len(expected_components)}
            if output.exists():
                document = json.loads(output.read_bytes())
                actual = graph(document, owner, npm_lock_wrapper=js and tool == 'trivy')
                components = {coord(c) for c in all_components(document) if coord(c)} - {owner}
                if js:
                    production = set(manifest.get('dependencies', {})) | set(manifest.get('optionalDependencies', {}))
                    dev_only = set(manifest.get('devDependencies', {})) - production
                    if actual is not None:
                        actual = {v for v in actual if v.removeprefix('pkg:npm/').rsplit('@', 1)[0] not in dev_only}
                    components &= production_packages
                row.update(status='GRAPH_UNKNOWN' if actual is None else 'MEASURED',
                           components=metrics(components, expected_components))
                if actual is not None:
                    row['direct'] = metrics(actual, expected)
            rows.append(row)
            atomic_json(out / 'summary.json', {'rows': rows, 'runtime_changed': False,
                        'limitation': 'Disclosed fixed corpus; source Maven mode and image npm manifest mode. No execution allowed. No claim of independent holdout gain.'})
            print(project, tool, row['status'], flush=True)


if __name__ == '__main__':
    main()

"""Initial source-mode competitor replay on existing Java/JS paired references."""
import json
import os
import subprocess
import time
from urllib.parse import unquote

from run import ROOT, atomic_json

NODE = 'C:/Users/prince74/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'


def coord(component):
    purl = component.get('purl', '').split('?')[0].split('#')[0]
    if not purl.startswith(('pkg:npm/', 'pkg:maven/')) or '@' not in purl:
        return None
    return unquote(purl)


def graph(document, owner, *, npm_lock_wrapper=False):
    components = list(document.get('components', []))
    root = document.get('metadata', {}).get('component')
    if root:
        components.append(root)
    by_ref = {c['bom-ref']: c for c in components if 'bom-ref' in c}
    owners = {c['bom-ref'] for c in components if coord(c) == owner}
    if not owners and npm_lock_wrapper:
        owners = {c['bom-ref'] for c in components if c.get('type') == 'application'
                  and c.get('name') == 'package-lock.json'
                  and {'name': 'aquasecurity:trivy:Type', 'value': 'npm'} in c.get('properties', [])}
    edges = [d for d in document.get('dependencies', []) if d['ref'] in owners]
    if len(edges) != 1:
        return None
    if any(ref not in by_ref for ref in edges[0].get('dependsOn', [])):
        return None
    return {coord(by_ref[ref]) for ref in edges[0].get('dependsOn', [])}


def main():
    out = ROOT / 'benchmarks/results/java-js-comparison-v1'
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for project, pair, kind in [('koa', 'koa-v1', 'js'), ('fastify', 'fastify-v1', 'js'),
                                 ('hapi', 'hapi-v3', 'js'), ('gson', 'gson-v1', 'java'),
                                 ('commons-text', 'commons-text-v1', 'java')]:
        source = ROOT / 'benchmarks/.work' / ('paired-' + pair) / 'src'
        for tool in ('trivy', 'cdxgen'):
            output = out / (project + '-' + tool + '.json')
            log = out / (project + '-' + tool + '.log')
            started = time.monotonic()
            reused = log.exists()
            if not log.exists():
                env = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
                env.update(TEMP=str(out), TMP=str(out))
                if tool == 'trivy':
                    args = [str(ROOT / 'benchmarks/.work/trivy-r34/trivy.exe'), 'fs', '--format', 'cyclonedx',
                            '--scanners', 'license', '--skip-db-update', '--skip-java-db-update', '--output', str(output), str(source)]
                else:
                    target = source / 'gson' if project == 'gson' else source
                    args = [NODE, '--permission', '--allow-fs-read=*', '--allow-fs-write=' + str(out),
                            str(ROOT / 'benchmarks/.work/cdxgen-r33/bin/cdxgen.js'), '-t', 'java' if kind == 'java' else 'js',
                            '--lifecycle', 'pre-build', '--no-install-deps', '--no-resolve-class', '--no-recurse',
                            '--spec-version', '1.6', '-o', str(output), str(target)]
                try:
                    result = subprocess.run(args, capture_output=True, env=env, timeout=120, check=False)
                    log.write_bytes(result.stdout + result.stderr)
                except subprocess.TimeoutExpired:
                    log.write_text('TIMEOUT', encoding='utf-8')
            # Oracle read only after competitor scan.
            reference = json.loads((ROOT / 'benchmarks/references' / ('paired-' + pair) / 'sbom.json').read_bytes())
            owner = coord(reference['metadata']['component'])
            expected = graph(reference, owner)
            row = {'project': project, 'tool': tool, 'mode': 'source prebuild, no project execution',
                   'expected_direct': len(expected) if expected is not None else None,
                   'elapsed_seconds': None if reused else round(time.monotonic() - started, 3),
                   'reused_scan': reused, 'status': 'NO_SBOM'}
            if output.exists():
                document = json.loads(output.read_bytes())
                actual = graph(document, owner, npm_lock_wrapper=tool == 'trivy' and kind == 'js')
                row.update(status='GRAPH_UNKNOWN' if actual is None else 'MEASURED',
                           component_count=len({coord(c) for c in document.get('components', []) if coord(c) and coord(c) != owner}))
                if actual is not None and expected is not None:
                    row.update(predicted_direct=len(actual), tp=len(actual & expected), fp=len(actual - expected),
                               fn=len(expected - actual), count_delta=len(actual) - len(expected))
            rows.append(row)
            atomic_json(out / 'summary.json', {'rows': rows, 'ranking': None, 'runtime_changed': False})
    print(json.dumps(rows))


if __name__ == '__main__':
    main()

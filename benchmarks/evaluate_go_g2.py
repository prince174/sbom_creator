"""Evaluate selected-main import candidates; reference graph never an input."""
import json
import subprocess

from go_g1_candidates import declarations, predict
from go_g2_imports import traverse
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json
from verify_paired_hey import json_stream


def main():
    helper = ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'
    binary_helper = ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'
    rows = []
    for work_name, ref_name in [('paired-hey-v1', 'paired-hey-v1'), ('go-multimain-r39', 'go-multimain-v2')]:
        work = ROOT / 'benchmarks/.work' / work_name
        binary = ROOT / 'benchmarks/.work/go-binary-info-r41' / (work_name + '.binary')
        info = json.loads(subprocess.check_output([str(binary_helper), str(binary)], timeout=30))
        settings = {s['Key']: s['Value'] for s in info['Settings']}
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=work / 'src', text=True).strip()
        if settings.get('vcs.revision') != commit or settings.get('vcs.modified') != 'false':
            raise ValueError('Binary commit not confirmed')
        if settings.get('CGO_ENABLED') != '0' or settings.get('-tags') or settings.get('GOAMD64') != 'v1' or any(settings.get(k) for k in ('-race', '-msan', '-asan', 'GOEXPERIMENT')):
            raise ValueError('Unsupported context')
        module, _ = declarations((work / 'src/go.mod').read_bytes())
        if (work / 'src/go.work').exists() or module != info['Main']['Path']:
            raise ValueError('Unsupported workspace/owner')
        entry = '.' if info['Path'] == module else info['Path'].removeprefix(module + '/')
        installed = {}
        for dep in info['Deps']:
            if dep.get('Replace') or dep['Path'] in installed:
                raise ValueError('Replace/ambiguous dependency')
            installed[dep['Path']] = dep['Version']
        index = json.loads(subprocess.check_output([str(helper), str(work / 'src'), settings['GOOS'], settings['GOARCH']], timeout=30))
        if index['parser_version'] != info['GoVersion']:
            raise ValueError('Parser context mismatch')
        prediction = traverse(module, entry, index, installed)
        g1 = predict((work / 'src/go.mod').read_bytes(), json.loads((work / 'analysis/image.syft.json').read_bytes()), commit)
        # Evaluation-only graph is read after predictions.
        out = ROOT / 'benchmarks/references' / ref_name
        receipt = json.loads((out / 'receipt.json').read_bytes())
        for name in ('packages.json', 'binary.sha256', 'go.mod', 'sbom.json'):
            if sha(out / name) != receipt['reference_hashes'][name]:
                raise ValueError('Reference changed')
        if sha(binary) != (out / 'binary.sha256').read_text().split()[0] or sha(work / 'src/go.mod') != sha(out / 'go.mod'):
            raise ValueError('Binary/source changed')
        packages = json_stream((out / 'packages.json').read_text())
        by_path = {p['ImportPath']: p for p in packages}
        expected = set()
        for pkg in packages:
            if pkg.get('Module', {}).get('Main'):
                for imported in pkg.get('Imports', []):
                    target = by_path[imported].get('Module', {})
                    if target and not target.get('Main'):
                        expected.add((target['Path'], target['Version']))
        actual = {tuple(r) for r in prediction['modules']}
        bom = json.loads((out / 'sbom.json').read_bytes())
        refs = root_dependencies(bom)
        module_declared = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
        old = {(r['name'], r['version']) for r in g1['candidates']}
        rows.append({'project': work_name, 'synthetic': work_name != 'paired-hey-v1', 'prediction': prediction,
                     'native_selected_main_direct': sorted(expected), 'candidate_matches': len(actual & expected),
                     'extra_candidates': len(actual - expected), 'missing_candidates': len(expected - actual),
                     'g1_extra_candidates': len(old - expected),
                     'cyclonedx_module_root_direct': sorted(module_declared),
                     'module_root_edges_without_g2_candidate': len(module_declared - actual)})
    report = {'experiment': 'R42', 'partition': 'one development repo plus synthetic derivative', 'rows': rows,
              'runtime_changed': False, 'direct_precision': None, 'direct_recall': None,
              'helper_source_sha256': sha(ROOT / 'benchmarks/go_source_index.go'),
              'limitation': 'Candidate graph, not production release. Native selected-main labels differ from CDX module-root declarations.'}
    atomic_json(ROOT / 'docs/go-g2-imports-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

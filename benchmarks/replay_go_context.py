"""Bounded frozen G2 replay through the experimental context gate."""
import hashlib
import json
import time

from go_g1_candidates import declarations
from go_g2_context import context
from go_g2_imports import traverse
from http_integration import command
from run import ROOT, atomic_json
from verify_paired_hey import json_stream

from sbom_creator.acquire import clean_environment, run_command


def main():
    frozen = json.loads((ROOT / 'benchmarks/go-g2-freeze-v1.json').read_bytes())['sha256']
    for name, digest in frozen.items():
        if hashlib.sha256((ROOT / 'benchmarks' / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen rules changed')
    rows = []
    for work_name, reference, binary_name, partition in [
        ('paired-hey-v1', 'paired-hey-v1', '../go-binary-info-r41/paired-hey-v1.binary', 'development'),
        ('go-multimain-r39', 'go-multimain-v2', '../go-binary-info-r41/go-multimain-r39.binary', 'synthetic-development'),
        ('paired-httprobe-v1', 'paired-httprobe-v1', 'payload.binary', 'fixed-control'),
        ('paired-lazygit-v1', 'paired-lazygit-v1', 'payload.binary', 'fixed-control')]:
        started = time.monotonic()
        work = ROOT / 'benchmarks/.work' / work_name
        source, binary = work / 'src', work / binary_name
        if not binary.is_file() or not 0 < binary.stat().st_size <= 32 * 1024 * 1024:
            raise ValueError('Payload outside bounded acquisition budget')
        commit = command(['git', '-C', str(source), 'rev-parse', 'HEAD'])
        if command(['git', '-C', str(source), 'status', '--porcelain']):
            raise ValueError('Source checkout dirty')
        env = clean_environment()
        def invoke(helper, args, work=work, env=env):
            return json.loads(run_command([str(helper), *args], cwd=work, env=env,
                              timeout=30, max_output_bytes=4 * 1024 * 1024, label='Passive Go helper'))
        info = invoke(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe', [str(binary)])
        module, _ = declarations((source / 'go.mod').read_bytes())
        gate = context(info, module, commit, workspace=(source / 'go.work').exists())
        if gate['status'] != 'ELIGIBLE_CANDIDATE':
            raise ValueError('Existing positive rejected: ' + gate.get('reason', ''))
        index = invoke(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe', [str(source), 'linux', 'amd64'])
        if index['parser_version'] != info['GoVersion']:
            raise ValueError('Parser context differs')
        prediction = traverse(module, gate['entry'], index, gate['installed'])
        actual = {tuple(v) for v in prediction['modules']}
        # References are opened only after prediction, for evaluation and integrity.
        out = ROOT / 'benchmarks/references' / reference
        receipt = json.loads((out / 'receipt.json').read_bytes())
        for name in ('packages.json', 'binary.sha256', 'go.mod', 'sbom.json'):
            if hashlib.sha256((out / name).read_bytes()).hexdigest() != receipt['reference_hashes'][name]:
                raise ValueError('Reference changed')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != (out / 'binary.sha256').read_text().split()[0]:
            raise ValueError('Binary changed')
        packages = json_stream((out / 'packages.json').read_text())
        by_path = {p['ImportPath']: p for p in packages}
        expected = set()
        for pkg in packages:
            if pkg.get('Module', {}).get('Main'):
                for imported in pkg.get('Imports', []):
                    target = by_path[imported].get('Module', {})
                    if target and not target.get('Main'):
                        expected.add((target['Path'], target['Version']))
        if actual != expected:
            raise ValueError('Selected-main candidates changed')
        rows.append({'project': work_name, 'partition': partition, 'gate': gate['status'],
                     'tp': len(actual & expected), 'fp': len(actual - expected), 'fn': len(expected - actual),
                     'precision': len(actual & expected) / len(actual) if actual else None,
                     'recall': len(actual & expected) / len(expected) if expected else None,
                     'elapsed_seconds': round(time.monotonic() - started, 3)})
    atomic_json(ROOT / 'docs/go-context-replay-v1.json', {'experiment': 'R53', 'rows': rows,
                'gate_coverage': {'eligible': 4, 'evaluated': 4}, 'runtime_changed': False,
                'label_scope': 'native selected-main imports, not CycloneDX module-root declarations',
                'limitation': 'Known cached fixtures; no new independent control or accuracy improvement'})
    print(json.dumps(rows))


if __name__ == '__main__':
    main()

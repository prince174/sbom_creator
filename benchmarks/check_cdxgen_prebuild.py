"""External competitor check with child processes denied; no oracle input."""
import argparse
import json
import os
import subprocess
from pathlib import Path

from paired_express import sha
from run import ROOT, atomic_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', required=True)
    args = parser.parse_args()
    tool = ROOT / 'benchmarks/.work/cdxgen-r33'
    work = ROOT / 'benchmarks/.work/cdxgen-results-r33'
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=tool, text=True).strip()
    if commit != 'b84786dec587a20deb605192087388fc0604b12d':
        raise ValueError('Unexpected competitor commit')
    rows = []
    for name in ('gson', 'commons-text'):
        source = ROOT / 'benchmarks/.work' / ('paired-' + name + '-v1') / 'src'
        if subprocess.check_output(['git', 'status', '--porcelain'], cwd=source, text=True).strip():
            raise ValueError('Source not clean')
        source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
        target = source / 'gson' if name == 'gson' else source
        output = work / (name + '.cdx.json')
        if output.exists():
            raise FileExistsError('Refusing to replace competitor output')
        command = [args.node, '--permission', '--allow-fs-read=*', '--allow-fs-write=' + str(work),
                   str(tool / 'bin/cdxgen.js'), '-t', 'java', '--lifecycle', 'pre-build', '--no-install-deps',
                   '--no-resolve-class', '--no-recurse', '--spec-version', '1.6', '-o', str(output), str(target)]
        env = {key: value for key, value in os.environ.items()
               if key.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
        env.update(TEMP=str(work), TMP=str(work))
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                env=env, timeout=120, check=False)
        raw = result.stdout + result.stderr
        (work / (name + '.clean-env.log')).write_text(raw, encoding='utf-8')
        denied = "permission: 'ChildProcess'" in raw and 'ERR_ACCESS_DENIED' in raw
        rows.append({'project': name, 'source_commit': source_commit, 'exit_code': result.returncode,
                     'child_process_denied': denied, 'sbom_generated': output.exists(),
                     'callsite': 'lib/cli/jvmBom.js:816', 'direct_precision': None, 'direct_recall': None})
    report = {'experiment': 'R33', 'competitor': 'cdxgen13.4.0', 'commit': commit,
              'node_version': subprocess.check_output([args.node, '--version'], text=True).strip(),
              'node_sha256': sha(Path(args.node)), 'lock_sha256': sha(tool / 'pnpm-lock.yaml'),
              'mode': 'java/pre-build/no-install-deps/no-resolve-class/no-recurse, Node child denied',
              'rows': rows, 'runtime_changed': False, 'holdout_read': False,
              'limitation': 'Mode compatibility failure; no accuracy measurement, not a test of build-enabled cdxgen'}
    atomic_json(ROOT / 'docs/cdxgen-prebuild-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

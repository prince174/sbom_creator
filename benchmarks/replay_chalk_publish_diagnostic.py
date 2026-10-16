"""One publisher-only diagnostic replay; no new scan, source input, or oracle."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def frames(error):
    """No message, exception arguments, local variables, or full host paths."""
    chain, seen = [], set()
    while error is not None and id(error) not in seen and len(chain) < 8:
        seen.add(id(error))
        rows, trace = [], error.__traceback__
        while trace is not None and len(rows) < 64:
            code = trace.tb_frame.f_code
            rows.append({'function': code.co_name, 'line': trace.tb_lineno,
                         'file': Path(code.co_filename).name})
            trace = trace.tb_next
        chain.append({'error_type': type(error).__name__, 'frames': rows})
        error = error.__cause__ or error.__context__
    return chain


def main():
    output = ROOT / 'benchmarks/results/chalk-publish-diagnostic-v1'
    if output.exists():
        raise FileExistsError('Preserve the single controlled diagnostic attempt')
    source = ROOT / 'benchmarks/results/mvp-r106-v1/java/executed-source/src'
    diagnostics = ROOT / 'benchmarks/results/mvp-r106-v1/javascript/paired-chalk-v1/analysis.diagnostics'
    inputs = {name: diagnostics / name for name in ('source.syft.json', 'image.syft.json', 'provenance.json')}
    syft = ROOT / '.tools/syft/syft.exe'
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'new_scans': False,
        'source_input': False, 'candidate': 'R106 already frozen executing source',
        'code_sha256': {p.relative_to(ROOT).as_posix(): sha(p)
                        for p in sorted(source.rglob('*')) if p.is_file() and p.suffix in ('.py', '.json')},
        'input_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in inputs.values()},
        'syft_sha256': sha(syft), 'runner_sha256': sha(Path(__file__))})
    shutil.copyfile(__file__, output / 'executed-runner.py')
    sys.path.insert(0, str(source))
    from sbom_creator.acquire import Settings
    from sbom_creator.core import rules_assessor
    from sbom_creator.pipeline import publish_catalogs

    data = {name: json.loads(path.read_bytes()) for name, path in inputs.items()}
    if data['provenance.json'].get('request', {}).get('repository_url') is not None:
        raise ValueError('The saved run must be image-only')
    started = time.monotonic()
    try:
        summary = publish_catalogs(data['source.syft.json'], data['image.syft.json'], output / 'analysis',
            Settings(syft_binary=str(syft), java_backend='disabled'), rules_assessor, data['provenance.json'])
        run = {'status': 'completed', 'summary': summary,
               'three_views_sha256': {view: sha(output / 'analysis' / (view + '.cdx.json'))
                                      for view in ('final', 'os', 'full')}}
    except Exception as error:  # noqa: BLE001 -- bounded, message-free exception-frame diagnostics
        run = {'status': 'FAILED', 'exception_frames': frames(error)}
    run.update(oracle_read=False, new_scans=False, source_input=False,
               elapsed_seconds=time.monotonic() - started,
               original_attempt_preserved=True)
    atomic_json(output / 'run.json', run)
    print(json.dumps({key: run[key] for key in ('status', 'elapsed_seconds')}))


if __name__ == '__main__':
    main()

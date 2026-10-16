"""Post-only evaluation after twelve frozen R109 JavaScript predictions."""
from __future__ import annotations

import json
import sys

from run import ROOT
from run_mvp_r106 import sha

OUTPUT = ROOT / 'benchmarks/results/mvp-js-types-r109-v1'


def prepare():
    from sbom_creator.validation import validate_cyclonedx

    marker = json.loads((OUTPUT / 'predictions-complete.json').read_bytes())
    freeze = json.loads((OUTPUT / 'freeze.json').read_bytes())
    cases = marker.get('cases', [])
    if (marker.get('oracle_read') is not False or len(cases) != 12 or len(set(cases)) != 12
            or cases != freeze.get('cases') or marker.get('freeze_sha256') != sha(OUTPUT / 'freeze.json')
            or freeze.get('fresh_scans') is not True or freeze.get('oracle_read') is not False
            or set(marker.get('completed', [])) | set(marker.get('failed', [])) != set(cases)
            or set(marker.get('completed', [])) & set(marker.get('failed', []))):
        raise ValueError('All twelve frozen prediction attempts must finish before oracle')
    if sha(ROOT / '.tools/syft/syft.exe') != freeze['syft_sha256']:
        raise ValueError('Pinned actual scanner/publisher changed')
    if sha(OUTPUT / 'executed-runner.py') != freeze['runner_sha256']:
        raise ValueError('Executing runner changed')
    for name, expected in freeze['code_sha256'].items():
        if sha(OUTPUT / 'executed-source' / name) != expected:
            raise ValueError('Executing source snapshot changed')
    for name, expected in freeze['input_sha256'].items():
        if sha(ROOT / name) != expected:
            raise ValueError('No-lock input image changed')
    prepared = []
    for name in cases:
        folder = OUTPUT / name
        invocation = json.loads((folder / 'invocation.json').read_bytes())
        run = json.loads((folder / 'run.json').read_bytes())
        if (invocation.get('oracle_read') is not False or run.get('oracle_read') is not False
                or invocation.get('source_input') is not False or invocation.get('fresh_scans') is not True
                or invocation.get('repository_url') is not None or invocation.get('commit') is not None
                or invocation.get('archive_sha256') != freeze['input_sha256'].get(invocation.get('archive'))):
            raise ValueError('Source/oracle/immutable image binding differs')
        analysis = folder / 'analysis'
        if run['status'] == 'completed':
            for view in ('final', 'os', 'full'):
                validate_cyclonedx(json.loads((analysis / (view + '.cdx.json')).read_bytes()))
            provenance = json.loads((analysis / 'provenance.json').read_bytes())
            if (provenance.get('source_kind') != 'not-provided'
                    or json.loads((analysis / 'source.syft.json').read_bytes())['artifacts']):
                raise ValueError('Prediction silently received source input')
        elif run['status'] == 'FAILED' and not analysis.exists():
            provenance, analysis = None, None
        else:
            raise ValueError('Unfinished publication')
        prepared.append((name, invocation, run, analysis, provenance))
    return prepared


def main():
    sys.path.insert(0, str(ROOT / 'src'))
    import evaluate_mvp_javascript as shared

    shared.OUTPUT = OUTPUT
    shared.prepared_outputs = prepare
    shared.main()


if __name__ == '__main__':
    main()

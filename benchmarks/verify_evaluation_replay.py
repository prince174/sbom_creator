"""Replay optional evaluator over existing immutable analysis outputs."""
import json

from run import ROOT, atomic_json

from sbom_creator.evaluation import compare


def main():
    rows = []
    for pair, expected in [('express-v1', (31, 0, 0)), ('axios-v2', (3, 0, 0)),
                           ('isarray-v1', (0, 0, 0)), ('koa-v1', (18, 0, 0)),
                           ('fastify-v1', (14, 0, 1)), ('hapi-v3', (18, 0, 0))]:
        reference = json.loads((ROOT / 'benchmarks/references' / ('paired-' + pair) / 'sbom.json').read_bytes())
        result = compare(ROOT / 'benchmarks/.work/runtime-npm-r19' / pair, reference, 'runtime')
        if tuple(result.get(k) for k in ('tp', 'fp', 'fn')) != expected:
            raise ValueError('Evaluator changed baseline metrics: ' + pair)
        if pair == 'isarray-v1' and any(result[k] is not None for k in ('precision', 'recall', 'f1')):
            raise ValueError('Empty metrics must remain null')
        rows.append({'project': pair, 'evaluation': result})
    atomic_json(ROOT / 'docs/evaluation-replay-v1.json', {'rows': rows, 'classifier_changed': False})
    print('Six existing real npm pairs reproduce baseline metrics; empty metrics null')


if __name__ == '__main__':
    main()

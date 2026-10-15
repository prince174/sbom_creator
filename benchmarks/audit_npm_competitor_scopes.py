"""Explain comparator excess edges using image manifest declarations."""
import json
from collections import Counter
from urllib.parse import unquote

from compare_java_js import coord, graph
from run import ROOT, atomic_json


def main():
    directory = ROOT / 'benchmarks/results/npm-image-manifests-v1'
    rows = []
    for project, pair in [('koa', 'koa-v1'), ('fastify', 'fastify-v1'), ('hapi', 'hapi-v3')]:
        manifest = json.loads((directory / (project + '-input/package.json')).read_bytes())
        for tool in ('trivy', 'cdxgen'):
            document = json.loads((directory / (project + '-' + tool + '.json')).read_bytes())
            owner = 'pkg:npm/' + manifest['name'] + '@' + manifest['version']
            actual = graph(document, owner, npm_lock_wrapper=tool == 'trivy')
            if actual is None:
                raise ValueError('Missing previously measured graph')
            # Scope normalization uses only the image manifest, before the oracle.
            production = set(manifest.get('dependencies', {})) | set(manifest.get('optionalDependencies', {}))
            dev_only = set(manifest.get('devDependencies', {})) - production
            normalized = {value for value in actual if unquote(value.removeprefix('pkg:npm/').rsplit('@', 1)[0]) not in dev_only}
            # Evaluation after scanner outputs and source declaration extraction.
            reference = json.loads((ROOT / 'benchmarks/references' / ('paired-' + pair) / 'sbom.json').read_bytes())
            expected = graph(reference, coord(reference['metadata']['component']))
            extras = []
            for value in sorted(actual - expected):
                name = unquote(value.removeprefix('pkg:npm/').rsplit('@', 1)[0])
                scopes = [field for field in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')
                          if name in manifest.get(field, {})]
                extras.append({'coordinate': value, 'declared_sections': scopes,
                               'explanation': 'declaration_scope_difference' if scopes else 'not_root_declared'})
            rows.append({'project': project, 'tool': tool, 'extras': extras,
                         'normalized_tp': len(normalized & expected), 'normalized_fp': len(normalized - expected),
                         'normalized_fn': len(expected - normalized),
                         'scope_counts': dict(Counter(section for e in extras for section in e['declared_sections']))})
    atomic_json(ROOT / 'docs/npm-competitor-scopes-v1.json', {'experiment': 'R66', 'rows': rows,
                'runtime_changed': False, 'limitation': 'Exploratory scope adapter on disclosed cases; no new independent control accuracy'})
    print(json.dumps([{k: v for k, v in r.items() if k != 'extras'} for r in rows]))


if __name__ == '__main__':
    main()

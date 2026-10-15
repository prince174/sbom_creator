"""Evaluate source owner graphs only after raw/projection prediction."""
import hashlib
import json

from http_integration import command
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from run import ROOT, atomic_json
from score_project_components import metrics
from trivy_pom_graph import extract


def main():
    registry = Registry()
    schemas = ROOT/'benchmarks/references/trivy-java-source-v1/schemas'
    for path in schemas.glob('*.json'):
        schema = json.loads(path.read_bytes())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    validator = Draft7Validator(json.loads((schemas/'bom-1.7.schema.json').read_bytes()), registry=registry)
    predictions = {}
    for mode, name in (('raw_offline', 'trivy-reactor-source-v1'), ('optional_projection_offline', 'trivy-reactor-source-optional-v1')):
        directory = ROOT/'benchmarks/results'/name
        if json.loads((directory/'run.json').read_bytes())['exit_code'] != 0:
            raise ValueError('Cannot evaluate failed source scan')
        document = json.loads((directory/'sbom.json').read_bytes())
        validator.validate(document)
        predictions[mode] = extract(document)
        atomic_json(directory/'owner-predictions.json', {'mode': mode, 'owners': predictions[mode], 'oracle_used': False,
                    'limitation': 'Candidate source-declared graphs; profiles and build activation not established; module containment may be mixed with dependencies in tool output'})
    # All predictions complete before the first reference read.
    pair = ROOT/'benchmarks/references/paired-javalin-reactor-v1'
    receipt = json.loads((pair/'receipt.json').read_bytes())
    for relative, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((pair/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Immutable reference changed')
    source = ROOT/'benchmarks/.work/paired-javalin-reactor-v1/src'
    if command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != receipt['commit'] or command(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('Source differs')
    labels = json.loads((pair/'module-labels.json').read_bytes())
    reports = []
    for mode, prediction in predictions.items():
        rows = []
        for label in labels:
            expected = {'pkg:maven/'+group+'/'+name+'@'+version for group, name, version in label['direct']}
            matches = [row for row in prediction if row['path'] == label['path']+'/pom.xml']
            owner = 'pkg:maven/'+'/'.join(label['owner'][:2])+'@'+label['owner'][2]
            row = matches[0] if len(matches) == 1 and matches[0]['owner'] == owner else None
            actual = set(row['direct']) if row else set()
            rows.append({'owner': owner, 'path': label['path'], 'shipped': bool(label['image_prefix']),
                         'direct': metrics(actual, expected), 'missing': sorted(expected-actual), 'extra': sorted(actual-expected),
                         'unknown_targets': row['unknown_targets'] if row else None,
                         'status': row['status'] if row else 'UNKNOWN_OWNER'})
        shipped = [row for row in rows if row['shipped']]
        tp, fp, fn = (sum(row['direct'][key] for row in shipped) for key in ('tp', 'fp', 'fn'))
        reports.append({'mode': mode, 'rows': rows, 'shipped_owners': len(shipped),
                        'shipped_direct': {'tp': tp, 'fp': fp, 'fn': fn, 'precision': tp/(tp+fp) if tp+fp else None,
                                           'recall': tp/(tp+fn) if tp+fn else None, 'f1': 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None},
                        'all_module_direct': {key: sum(row['direct'][key] for row in rows) for key in ('tp', 'fp', 'fn')}})
    atomic_json(ROOT/'benchmarks/results/trivy-reactor-source-optional-v1/evaluation.json', {'development_only': True,
                'source_clean_verified': True, 'schemas_valid': True, 'reports': reports, 'runtime_changed': False,
                'limitation': 'One disclosed development project. Source graphs do not prove activated production scope or runtime use. POM-only containment edges preserved as extras. Online projection failed Maven429; no score for failed scan. No holdout or acceptance claim.'})
    print(json.dumps([{row['mode']: row['shipped_direct']} for row in reports]))


if __name__ == '__main__':
    main()

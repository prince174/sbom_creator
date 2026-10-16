"""Post-only R104 control: native cdxgen versus passive source owner edges."""
import json

from compare_java_js import coord, graph
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import read, reference
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    output = ROOT / 'benchmarks/results/java-runtime-direct-r104-control-v1'
    destination = output / 'evaluation.json'
    if destination.exists():
        raise FileExistsError('Preserve completed evaluation')
    passive = read(output / 'microservices-source.json')
    cdxgen_run = read(output / 'cdxgen/run.json')
    if cdxgen_run.get('oracle_read') is not False or cdxgen_run.get('returncode') != 0:
        raise ValueError('Completed no-oracle native prediction required')
    cdxgen = read(output / 'cdxgen/sbom.json')
    # Oracle access only after both independent predictions are complete.
    folder = ROOT / 'benchmarks/references/paired-petclinic-microservices-r104'
    receipt = reference(folder)
    if cdxgen_run['source_commit'] != receipt['commit']:
        raise ValueError('Source commit binding differs')
    rows = []
    for label in read(folder / 'module-labels.json'):
        module = folder / 'modules' / ('root' if label['path'] == '.' else label['path'])
        owner = coord(read(module / 'sbom.json')['metadata']['component'])
        expected = {'pkg:maven/' + group + '/' + name + '@' + version
                    for group, name, version in label['direct']}
        actual = {edge['component'] for edge in passive['edges']
                  if edge.get('status') == 'DIRECT' and edge.get('owner') == owner}
        native = graph(cdxgen, owner)
        rows.append({'module': label['path'], 'owner': owner,
                     'shipped': bool(label['image_prefix']),
                     'passive_trivy': metrics(actual, expected),
                     'cdxgen_raw': metrics(native or set(), expected),
                     'cdxgen_graph_status': 'MEASURED' if native is not None else 'UNKNOWN',
                     'passive_missing': sorted(expected - actual),
                     'cdxgen_extra': sorted((native or set()) - expected),
                     'cdxgen_missing': sorted(expected - (native or set()))})
    shipped = [row for row in rows if row['shipped']]
    report = {'project': receipt['project'], 'commit': receipt['commit'], 'runtime_integration': False,
              'partition': 'development source control; not independent global acceptance',
              'rows': rows,
              'passive_all_module_direct': aggregate([r['passive_trivy'] for r in rows]),
              'cdxgen_raw_all_module_direct': aggregate([r['cdxgen_raw'] for r in rows]),
              'cdxgen_shipped_module_direct': aggregate([r['cdxgen_raw'] for r in shipped]),
              'passive_owner_coverage': passive.get('owner_coverage'),
              'native_seconds': cdxgen_run.get('seconds'),
              'limitations': ['Module-containment root edges remain raw cdxgen FP; not silently relabelled',
                             'Native Maven model scope is analysis configuration, not arbitrary original CI reproduction',
                             'GAV/version direct identity labels; classifier/type-qualified accuracy not established',
                             'Repository graph and source-only declarations are not image component evidence',
                             'Subsequent production source changes are not validated by this historical prediction']}
    atomic_json(destination, report)
    print(json.dumps({key: value for key, value in report.items() if key.endswith('direct')}))


if __name__ == '__main__':
    main()

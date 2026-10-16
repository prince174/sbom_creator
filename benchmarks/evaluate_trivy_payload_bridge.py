"""Only post-publication evaluation reads build references and module labels."""
import hashlib
import json

from compare_java_js import all_components, coord
from run import ROOT, atomic_json
from score_project_components import metrics


def read(path):
    return json.loads(path.read_bytes())


def reference(pair):
    receipt = read(pair / 'receipt.json')
    for name, expected in receipt['reference_hashes'].items():
        assert hashlib.sha256((pair / name).read_bytes()).hexdigest() == expected
    return receipt


def projected(document, prefix, owner):
    return {coord(c) for c in all_components(document) if coord(c) and any(
        p.get('name', '').startswith('syft:location:') and p.get('name', '').endswith(':path')
        and p.get('value', '').startswith(prefix) for p in c.get('properties', []))} - {owner}


def versions(actual, expected):
    matched = {x for x in expected if any(y.rsplit('@', 1)[0] == x.rsplit('@', 1)[0] for y in actual)}
    return {'version_accuracy_matched_identity': len(actual & expected) / len(matched) if matched else None,
            'exact_version_coverage': len(actual & expected) / len(expected) if expected else None}


def main(output=None):
    output = output or ROOT / 'benchmarks/results/trivy-payload-bridge-v1'
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve completed evaluation')
    freeze = read(output / 'candidate-freeze.json')
    for name, expected in {**freeze['code_sha256'], **freeze['input_sha256']}.items():
        with (ROOT / name).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected
    for case in ('boot', 'javalin'):
        run = read(output / case / 'run.json')
        assert run['three_views_schema_valid'] and run['oracle_read'] is False
    # Oracle access starts here, after both predictions and all six SBOMs.
    boot = ROOT / 'benchmarks/references/paired-spring-petclinic-v1'
    receipt = reference(boot)
    labels = read(ROOT / 'benchmarks/results/boot-packaging-labels-v3/report.json')
    assert labels['commit'] == receipt['commit']
    owner = coord(read(boot / 'sbom.json')['metadata']['component'])
    actual = projected(read(output / 'boot/final.cdx.json'), '/application/', owner)
    expected = set(labels['packaged'])
    boot_result = {'components': metrics(actual, expected), **versions(actual, expected),
                   'component_count_delta': len(actual) - len(expected),
                   'missing': sorted(expected - actual), 'extra': sorted(actual - expected),
                   'packaging_unknown_charged_fp': len(labels['unknown_packaged']),
                   'direct_unknown_charged_fn': len(labels['root_direct_build']),
                   'direct': metrics(set(), set(labels['root_direct_build'])),
                   'baseline_bounded_syft': read(ROOT / 'benchmarks/results/bounded-boot-evidence-v2/evaluation.json')['component_exact_micro']}
    javalin = ROOT / 'benchmarks/references/paired-javalin-reactor-v1'
    reference(javalin)
    final = read(output / 'javalin/final.cdx.json')
    rows = []
    for label in read(javalin / 'module-labels.json'):
        if not label['image_prefix']:
            continue
        bom = read(javalin / 'modules' / label['path'] / 'sbom.json')
        owner = coord(bom['metadata']['component'])
        expected = {coord(c) for c in all_components(bom) if coord(c)} - {owner}
        actual = projected(final, label['image_prefix'], owner)
        native = read(javalin / 'modules' / label['path'] / 'dependency-tree.json')
        pending = list(native.get('children', []))
        native_components = set()
        for node in pending:
            native_components.add(f"pkg:maven/{node['groupId']}/{node['artifactId']}@{node['version']}")
            pending.extend(node.get('children', []))
        agreed = expected == native_components
        rows.append({'path': label['path'], 'owner': label['owner'],
                     'scope': 'NATIVE_CDX_AGREEMENT' if agreed else 'UNKNOWN_NATIVE_CDX_TRANSITIVE_MISMATCH',
                     'components': metrics(actual, expected) if agreed else None,
                     'raw_build_reference_delta': metrics(actual, expected),
                     'version_metrics': versions(actual, expected) if agreed else None,
                     'count_delta': len(actual) - len(expected),
                     'missing': sorted(expected - actual), 'extra': sorted(actual - expected),
                     'direct_unknown_charged_fn': len(label['direct'])})
    scored = [row['components'] for row in rows if row['components'] is not None]
    tp, fp, fn = (sum(row[key] for row in scored) for key in ('tp', 'fp', 'fn'))
    micro = {'tp': tp, 'fp': fp, 'fn': fn, 'precision': tp / (tp + fp),
             'recall': tp / (tp + fn), 'f1': 2 * tp / (2 * tp + fp + fn)}
    macro = {key: sum(row[key] for row in scored) / len(scored) for key in ('precision', 'recall', 'f1')}
    atomic_json(output / 'evaluation.json', {'runtime_changed': False, 'partition': 'disclosed_development_only',
                'boot': boot_result, 'javalin': {'rows': rows, 'components_micro': micro, 'components_macro': macro,
                'scored_owners': len(scored), 'scope_unknown_owners': len(rows) - len(scored),
                'direct_unknown_charged_fn': sum(row['direct_unknown_charged_fn'] for row in rows)},
                'acceptance': False, 'three_views_each_retained': True,
                'limitations': ['No independent control or production integration',
                               'Raw peer inventory is not substituted for service final; unbound artifacts remain UNKNOWN',
                               'Image graph is never used as direct graph; source-owner integration absent',
                               'Macro is across module owners of one repository, not independent projects',
                               'Cached replay timing excludes scanning/acquisition; peak RSS unknown']})
    print(json.dumps({'boot': boot_result['components'], 'javalin': micro, 'scope_unknown_owners': len(rows) - len(scored)}))


if __name__ == '__main__':
    main()

"""Post-analysis loss accounting; never a predictor input."""
import json

from run import ROOT, atomic_json
from score_project_components import metrics
from trivy_payload_bridge import canonical_path, properties


def read(path):
    return json.loads(path.read_bytes())


def main():
    output = ROOT / 'benchmarks/results/trivy-payload-bridge-v1'
    if (output / 'coverage.json').exists():
        raise FileExistsError('Preserve completed report')
    evaluation = read(output / 'evaluation.json')
    cases = {}
    for case in ('boot', 'javalin'):
        audit = read(output / case / 'bridge.json')
        peer = read(output / case / 'peer-image.cdx.json')
        bound = {tuple(row['path_layer']) for row in audit['packages'] if row['status'] == 'BOUND'}
        unknown = []
        for component in peer['components']:
            if not component.get('purl', '').startswith('pkg:maven/'):
                continue
            paths, layers = properties(component, 'FilePath'), properties(component, 'LayerDiffID')
            if len(paths) == len(layers) == 1 and (canonical_path(paths[0]), layers[0]) not in bound:
                unknown.append({'purl': component['purl'], 'path': paths[0], 'layer': layers[0]})
        cases[case] = {'peer_packages_without_bound_witness': unknown,
                       'syft_java_unknown': [row for row in audit['packages'] if row['status'] == 'UNKNOWN']}
    labels = read(ROOT / 'benchmarks/references/paired-javalin-reactor-v1/module-labels.json')
    expected = {(row['path'], tuple(dep)) for row in labels if row['image_prefix'] for dep in row['direct']}
    direct_path = ROOT / 'benchmarks/.work/paired-javalin-reactor-v1/analysis-trivy-payload-bridge-v1/direct-dependencies.json'
    assert not read(direct_path)['edges']
    cases['javalin']['known_shipped_direct_metrics'] = metrics(set(), expected)
    raw = read(ROOT / 'benchmarks/results/trivy-boot-image-v1/evaluation.json')['components_conservative_extra_as_fp']
    cases['boot']['raw_peer_components'] = raw
    cases['boot']['final_components'] = evaluation['boot']['components']
    cases['boot']['additional_fn_vs_raw_peer'] = evaluation['boot']['components']['fn'] - raw['fn']
    atomic_json(output / 'coverage.json', {'cases': cases, 'runtime_changed': False,
                'post_analysis_only': True,
                'limitation': 'Intersection requires Syft archive catalog entry; Trivy-only resource JAR is lost. This extra FN must not be hidden or accepted as coverage-neutral integration.'})
    print(json.dumps({'boot_extra_fn_vs_raw': cases['boot']['additional_fn_vs_raw_peer'],
                      'javalin_known_direct': cases['javalin']['known_shipped_direct_metrics']}))


if __name__ == '__main__':
    main()

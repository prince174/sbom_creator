"""Summarize completed measurements; no prediction or reference construction."""
import hashlib
import json
import shutil
from pathlib import Path

from report_mvp_r109 import combine
from run import ROOT, atomic_json


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    output = ROOT / 'benchmarks/results/mvp-r110-summary-v1'
    if output.exists():
        raise FileExistsError('Preserve completed report')
    paths = {key: ROOT / 'benchmarks/results' / value for key, value in {
        'prior': 'mvp-r109-summary-v1/report.json',
        'held': 'mvp-r110-held-controls-v1/evaluation.json',
        'installed': 'mvp-r110-container-v1/parity.json',
        'javascript_regression': 'mvp-r110-js-publish-v1/report.json'}.items()}
    documents = {key: json.loads(path.read_bytes()) for key, path in paths.items()}
    prior, held = documents['prior'], documents['held']
    js = documents['javascript_regression']
    if js.get('status') != 'passed' or len(js.get('cases', [])) != 12 or any(
            row.get('status') != 'passed' for row in js['cases']):
        raise ValueError('All twelve default-config JS regressions must pass')
    micro = combine([prior['java']['components_micro'], held['java_components_micro']])
    macro = {key: (prior['java']['components_macro_across_four_repositories'][key] * 4
                   + held['java_components_macro_across_projects'][key] * 2) / 6
             for key in ('precision', 'recall', 'f1')}
    matched = round(prior['java']['components_micro']['tp'] / prior['java']['conditional_version_accuracy'])
    matched += sum(round(row['components']['tp'] / row['versions']['version_accuracy_matched_identity'])
                   for row in held['reports'].values())
    result = {'mode': 'release default adoption; combined distinct completed known-delivered scopes',
        'java': {'components_micro': micro, 'components_repository_macro': macro,
            'known_reference_instances': micro['tp'] + micro['fn'],
            'predicted_instances': micro['tp'] + micro['fp'],
            'count_delta': micro['fp'] - micro['fn'],
            'exact_version_coverage_known_delivered': micro['recall'],
            'conditional_version_accuracy': micro['tp'] / matched,
            'matched_identity_instances': matched,
            'known_owner_instances': 59, 'repositories': 6,
            'fresh_r110_controls': ['rest', 'dbcp'],
            'prior_four_repositories': 'R108 predictions/R109 POST-only packaged scoring, not fresh R110 scans',
            'runtime_reader_identity_algorithms_changed': False,
            'default_archive_components': True, 'nested_selector_default': False,
            'held_controls_metadata_only_archive_proofs': 0,
            'metadata_only_real_evidence': 'R108 disclosed Micro/Drop 201 proofs, not a fresh metadata-only control',
            'image_only_direct_unknown_fn': 638,
            'global_shaded_component_completeness': 'UNKNOWN'},
        'javascript': prior['javascript'],
        'javascript_measurement': 'R109 twelve fresh no-lock scans; R110 cached publisher regression only',
        'javascript_image_only_direct_unknown_fn': 103,
        'installed_default_semantic_views_equal': all(
            row['coordinate_multisets_equal'] for row in documents['installed']['views'].values()),
        'installed_full_parity_status': documents['installed']['status'],
        'universal_accuracy_or_blind_independence_claim': False,
        'deployed_service_changed': False,
        'remaining': ['Known delivered JAR scope is not complete opaque/shaded inventory attestation',
            'Known Hibernate/ambiguous identities and conservative packaging extras remain',
            'JS delivered fixture extras remain conservative FP in dependency-reference scoring',
            'Cold DB download/recovery, hard quota and parallel-job acceptance not established',
            'OS producer IDs/raw UNKNOWN observations vary across platforms'],
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in paths.values()}}
    output.mkdir()
    shutil.copyfile(__file__, output / 'executed-script.py')
    atomic_json(output / 'report.json', result)
    print(json.dumps({'java': micro, 'macro': macro, 'javascript': prior['javascript']['components_micro']}))


if __name__ == '__main__':
    main()

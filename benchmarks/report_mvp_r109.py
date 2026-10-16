"""Combine already completed reports; never predict or construct truth."""
import hashlib
import json
import shutil
from pathlib import Path

from run import ROOT, atomic_json


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def combine(rows):
    result = {key: sum(row[key] for row in rows) for key in ('tp', 'fp', 'fn')}
    t, p, n = (result[key] for key in ('tp', 'fp', 'fn'))
    result.update(precision=t/(t+p) if t+p else None, recall=t/(t+n) if t+n else None,
                  f1=2*t/(2*t+p+n) if 2*t+p+n else None)
    return result


def main():
    output = ROOT / 'benchmarks/results/mvp-r109-summary-v1'
    if output.exists():
        raise FileExistsError('Preserve completed summary')
    inputs = {name: ROOT / 'benchmarks/results' / relative for name, relative in {
        'packaged_java': 'reactor-packaged-evaluation-r109-v3/evaluation.json',
        'old_java': 'mvp-r108-v1/evaluation.json',
        'javascript': 'mvp-js-types-r109-v1/evaluation.json',
        'installed': 'mvp-r109-container-v1/parity.json',
        'java_regression': 'mvp-r109-java-publish-v1/report.json',
        'validation': 'mvp-r109-final-validation.json'}.items()}
    documents = {name: json.loads(path.read_bytes()) for name, path in inputs.items()}
    java = documents['packaged_java']
    boot = documents['old_java']['reports']['boot']
    reports = {**java['reports'], 'boot': {'known_delivered_conservative_micro': boot['components']}}
    rows = [r['known_delivered_conservative_micro'] for r in reports.values()]
    micro = combine(rows)
    matched = sum(r['versions']['matched_identity_count'] for r in java['reports'].values()) + round(boot['components']['tp'] / boot['versions']['version_accuracy_matched_identity'])
    exact = micro['tp']
    result = {'mode': 'post-only summary of distinct measured scopes; not a new prediction',
        'java': {'prediction_version': 'frozen R108 v7',
            'scope': 'known delivered standalone/nested archive GAVs; conservative extras, incomplete global shading scope',
            'components_micro': micro,
            'components_macro_across_four_repositories': {key: sum(r[key] for r in rows)/len(rows)
                for key in ('precision', 'recall', 'f1')},
            'predicted_instances': micro['tp']+micro['fp'],
            'known_reference_instances': micro['tp']+micro['fn'],
            'count_delta': micro['fp']-micro['fn'],
            'conditional_version_accuracy': exact/matched,
            'exact_version_coverage_known_delivered': micro['recall'],
            'owners_with_known_reference': 57, 'reactor_archive_complete_owners': 47,
            'reactor_owner_count': 56, 'global_shaded_component_completeness': 'UNKNOWN',
            'historical_r108_metrics_unchanged': True},
        'javascript': {key: documents['javascript'][key] for key in
            ('components_micro', 'components_macro_positive_projects', 'projects',
             'positive_component_projects', 'components_exact_identity_regression')},
        'javascript_fresh_scans': True, 'javascript_new_policy': 'image-evidence-and-payload-v4',
        'java_default_archive_components': False, 'java_v7_opt_in_unchanged': True,
        'installed_non_os_parity': documents['installed']['views']['final']['coordinate_multisets_equal'],
        'installed_full_parity': documents['installed']['status'],
        'acceptance': False,
        'limitations': ['Known-delivered recall is not global component recall for opaque/shaded code',
            'No fresh blind independence: source rules are tuned on disclosed Nest',
            'Existing delivered fixture extras remain conservative FP against build-reference scope',
            'OS/full Windows versus Linux systemd delta is preserved',
            'Direct graph remains a separate image-only UNKNOWN axis'],
        'input_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in inputs.values()}}
    output.mkdir()
    shutil.copyfile(__file__, output / 'executed-script.py')
    atomic_json(output / 'report.json', result)
    print(json.dumps({'java': micro, 'javascript': result['javascript']['components_micro']}))


if __name__ == '__main__':
    main()

"""Post-only classification of retained missing-component evidence; no prediction."""
from __future__ import annotations

import json
from collections import Counter

from compare_java_js import coord
from evaluate_mvp_r106 import view_regression
from evaluate_trivy_payload_bridge import read
from run import ROOT, atomic_json


def main():
    output = ROOT / 'benchmarks/results/mvp-r106-v1'
    if not (output / 'evaluation.json').is_file():
        raise ValueError('Completed post-only evaluation is required')
    destination = output / 'microservices-diagnosis.json'
    if destination.exists():
        raise FileExistsError('Preserve completed diagnosis')
    evaluated = read(output / 'java/evaluation.json')['reports']['microservices']
    rows = [row for row in evaluated['rows'] if row['components'] is not None]
    if len(rows) != 1:
        raise ValueError('Expected the unchanged single scope-agreeing owner')
    row = rows[0]
    audit = read(output / 'java/microservices/analysis/image-identity-audit.json')
    packages = audit['binding']['existing_bridge']['packages']
    diagnoses = []
    for identity in row['missing']:
        observed = [item for item in packages
                    if (coord(item.get('original', {})) == identity or item.get('identity') == identity)
                    and item.get('path_layer', [''])[0].startswith(row['image_prefix'])]
        physical = [item for item in observed if item.get('observed_payload', {}).get('status') == 'confirmed']
        if physical:
            category = 'PHYSICAL_PRESENT_IDENTITY_UNBOUND'
        elif any(item.get('observed_payload', {}).get('error_type') == 'BudgetExceeded' for item in observed):
            category = 'BOUNDED_READ_UNKNOWN_BUDGET_TYPE_NOT_RETAINED'
        elif observed:
            category = 'NO_CONFIRMED_PHYSICAL_WITNESS'
        else:
            category = 'NOT_MATCHED_IN_EXISTING_SYFT_BRIDGE_AUDIT'
        diagnoses.append({'component': identity, 'category': category,
            'observations': [{key: item.get(key) for key in
                             ('original', 'status', 'reason', 'path_layer', 'observed_payload')}
                             for item in observed]})
    result = {'post_analysis_only': True, 'classifier_rules_changed': False,
              'new_scans_or_physical_reads': False, 'owner': row['owner'],
              'components': row['components'], 'extra': row['extra'],
              'category_counts': dict(Counter(item['category'] for item in diagnoses)),
              'missing': diagnoses,
              'resource_audit': {key: audit[key] for key in ('jar_resources', 'layer_resources')},
              'budget_cause': 'UNKNOWN: safe original audit retains only BudgetExceeded class, not failing guard',
              'limitations': ['Diagnosis uses evaluated misses after publication and must never become predictor input',
                              'No bound or identity rule is relaxed based on the reference',
                              'Packaging-added jarmode remains conservative FP; no oracle-filtered removal']}
    atomic_json(destination, result)
    diagnostic = ROOT / 'benchmarks/results/chalk-publish-diagnostic-v1'
    atomic_json(diagnostic / 'r105-view-regression.json', view_regression(
        diagnostic / 'analysis', ROOT / 'benchmarks/results/mvp-js-r105-v1/paired-chalk-v1/analysis'))
    print(json.dumps(result['category_counts']))


if __name__ == '__main__':
    main()

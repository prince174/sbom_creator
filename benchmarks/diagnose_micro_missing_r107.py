"""Post-only explanation of R106's twelve unmatched-original-PURL misses.

Read stored predictions and the completed evaluator only. This never reads image
bytes, starts a scanner/build, changes classifier rules, or predicts a component.
The report must not be supplied to a classifier as an input or expected-name list.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path

from packageurl import PackageURL
from run import ROOT, atomic_json

OUTPUT = ROOT / 'benchmarks/results/micro-missing-diagnosis-r107-v1'
PREDICTION = ROOT / 'benchmarks/results/mvp-r106-v1'
ANALYSIS = PREDICTION / 'java/microservices/analysis'
MAX_JSON_BYTES = 128 * 1024 * 1024
MAX_ITEMS = 100_000
MAX_OBSERVATIONS_PER_MISS = 32


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError('Stored JSON exceeds diagnostic input budget')
    return json.loads(path.read_bytes())


def coordinate(value):
    purl = PackageURL.from_string(value)
    if purl.type != 'maven' or not purl.namespace or not purl.version:
        raise ValueError('Expected complete Maven coordinate')
    return PackageURL(type='maven', namespace=purl.namespace,
                      name=purl.name, version=purl.version).to_string()


def properties(component, suffix):
    return [entry.get('value') for entry in component.get('properties', [])
            if entry.get('name') == 'aquasecurity:trivy:' + suffix]


def peer_path(value):
    """Display/join normalization already used by the frozen bridge; no aliases."""
    if (not isinstance(value, str) or '\\' in value or ':' in value or value.startswith('//')
            or any(part in ('', '.', '..') for part in value.lstrip('/').split('/'))):
        raise ValueError('Unexpected stored peer path')
    return '/' + value.lstrip('/')


def flatten(document):
    pending = list(document.get('components', []))
    result = []
    while pending:
        component = pending.pop()
        result.append(component)
        if len(result) > MAX_ITEMS:
            raise ValueError('Stored component count budget')
        pending.extend(component.get('components', []))
    return result


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve completed or attempted post-only diagnosis')
    inputs = {
        'completed_predictions': PREDICTION / 'predictions-complete.json',
        'completed_evaluation': PREDICTION / 'evaluation.json',
        'java_evaluation': PREDICTION / 'java/evaluation.json',
        'prior_diagnosis': PREDICTION / 'microservices-diagnosis.json',
        'original_syft': ANALYSIS / 'image-original.syft.json',
        'peer': ANALYSIS / 'image-peer.cdx.json',
        'audit': ANALYSIS / 'image-identity-audit.json',
    }
    records = {name: {'path': path.relative_to(ROOT).as_posix(),
                      'bytes': path.stat().st_size, 'sha256': sha(path)}
               for name, path in inputs.items()}
    marker = read(inputs['completed_predictions'])
    if marker.get('oracle_read') is not False or not inputs['completed_evaluation'].is_file():
        raise ValueError('Completed post-prediction evaluation required')
    prior, evaluated = read(inputs['prior_diagnosis']), read(inputs['java_evaluation'])
    owner_rows = [row for row in evaluated['reports']['microservices']['rows']
                  if row.get('components') is not None]
    if len(owner_rows) != 1 or owner_rows[0]['owner'] != prior['owner']:
        raise ValueError('The existing single scored owner changed')
    owner = owner_rows[0]
    misses = [row['component'] for row in prior['missing']
              if row['category'] == 'NOT_MATCHED_IN_EXISTING_SYFT_BRIDGE_AUDIT']
    if len(misses) != 12 or len(set(misses)) != 12:
        raise ValueError('Expected the twelve prior unmatched-original-PURL misses')
    original, peer, audit = read(inputs['original_syft']), read(inputs['peer']), read(inputs['audit'])
    artifacts = original.get('artifacts', [])
    audit_rows = audit['binding']['existing_bridge']['packages']
    if len(artifacts) > MAX_ITEMS or len(audit_rows) > MAX_ITEMS:
        raise ValueError('Stored package count budget')
    by_id = {row['original']['id']: row for row in audit_rows}
    if len(by_id) != len(audit_rows):
        raise ValueError('Ambiguous audit artifact IDs')
    config = original['source']['metadata']['imageID']
    peer_config = properties(peer['metadata']['component'], 'ImageID')
    if peer_config != [config] or audit['binding']['existing_bridge']['image_config_digest'] != config:
        raise ValueError('Stored image config bindings differ')
    components = flatten(peer)
    peers = defaultdict(list)
    for component in components:
        if not component.get('purl', '').startswith('pkg:maven/'):
            continue
        paths, layers = properties(component, 'FilePath'), properties(component, 'LayerDiffID')
        if len(paths) == len(layers) == 1:
            peers[peer_path(paths[0]), layers[0]].append(component)
    rows = []
    for expected in misses:
        identity = PackageURL.from_string(expected)
        candidates = [artifact for artifact in artifacts
                      if artifact.get('name') == identity.name and artifact.get('version') == identity.version
                      and any(location.get('path', '').startswith(owner['image_prefix'])
                              for location in artifact.get('locations', []))]
        if len(candidates) > MAX_OBSERVATIONS_PER_MISS:
            raise ValueError('Per-miss diagnostic observation budget')
        observations = []
        for artifact in candidates:
            observation = by_id.get(artifact['id'])
            if observation is None or not observation.get('path_layer'):
                raise ValueError('Expected an existing path/layer-bound audit observation')
            key = tuple(observation['path_layer'])
            peer_rows = peers.get(key, [])
            peer_records = [{'ref': component.get('bom-ref'), 'purl': component.get('purl'),
                             'raw_file_path': properties(component, 'FilePath')[0],
                             'canonical_file_path': key[0], 'layer_diff_id': key[1],
                             'canonical_gav': coordinate(component['purl'])}
                            for component in peer_rows]
            metadata = artifact.get('metadata', {})
            observations.append({
                'syft_artifact_id': artifact['id'], 'found_by': artifact.get('foundBy'),
                'original_purl': artifact.get('purl'), 'original_canonical_gav': coordinate(artifact['purl']),
                'name_version_equal_expected': True,
                'original_namespace': PackageURL.from_string(artifact['purl']).namespace,
                'expected_namespace': identity.namespace,
                'original_namespace_equals_artifact_name': PackageURL.from_string(artifact['purl']).namespace == identity.name,
                'exact_original_gav_matches_expected': coordinate(artifact['purl']) == coordinate(expected),
                'outer_locations': [{'path': location.get('path'), 'layer_id': location.get('layerID'),
                                     'access_path': location.get('accessPath')}
                                    for location in artifact.get('locations', [])],
                'virtual_path': metadata.get('virtualPath'), 'metadata_fields': sorted(metadata),
                'audit_path_layer': list(key), 'audit_status': observation['status'],
                'audit_reason': observation.get('reason'),
                'observed_payload': observation.get('observed_payload'),
                'peer_at_exact_path_layer': peer_records,
                'unique_peer_exact_expected_gav': len(peer_records) == 1
                    and peer_records[0]['canonical_gav'] == coordinate(expected),
            })
        rows.append({'expected_gav_post_only': expected, 'observations': observations,
                     'matched_by_original_gav': sum(row['exact_original_gav_matches_expected'] for row in observations),
                     'matched_by_name_version_and_same_path_layer_peer': sum(
                         row['unique_peer_exact_expected_gav'] for row in observations),
                     'all_observed_payload_budget_unknown': bool(observations) and all(
                         row['observed_payload'].get('status') == 'unconfirmed'
                         and row['observed_payload'].get('error_type') == 'BudgetExceeded'
                         for row in observations),
                     'category': 'ORIGINAL_SYFT_NAMESPACE_DIFFERS_PEER_HAS_EXPECTED_GAV_AT_BOUND_PATH_BUT_PAYLOAD_BUDGET_UNKNOWN'})
    observations = [row for item in rows for row in item['observations']]
    if not observations or not all(row['unique_peer_exact_expected_gav'] for row in observations):
        raise ValueError('Unexpected peer/path ambiguity; do not generalize the category')
    if not all(item['all_observed_payload_budget_unknown'] for item in rows):
        raise ValueError('Unexpected non-budget observation; retain distinct categories')
    atomic_json(OUTPUT / 'input-manifest.json', {'post_analysis_only': True,
        'inputs': records, 'script_sha256': sha(Path(__file__)),
        'bounds': {'json_bytes_each': MAX_JSON_BYTES, 'items_each': MAX_ITEMS,
                   'observations_per_miss': MAX_OBSERVATIONS_PER_MISS}})
    shutil.copyfile(__file__, OUTPUT / 'executed-script.py')
    report = {'post_analysis_only': True, 'predictor_input_forbidden': True,
        'new_scans_builds_image_reads_or_classifier_edits': False,
        'image_config_digest': config, 'owner': owner['owner'], 'image_prefix': owner['image_prefix'],
        'original_component_metrics_unchanged': owner['components'],
        'counts': {'prior_unmatched_gav_misses': len(rows), 'actual_syft_observations': len(observations),
                   'exact_original_gav_matches': sum(row['exact_original_gav_matches_expected'] for row in observations),
                   'same_path_layer_unique_peer_expected_gav': sum(row['unique_peer_exact_expected_gav'] for row in observations),
                   'budget_unknown_observations': sum(row['observed_payload'].get('error_type') == 'BudgetExceeded'
                                                      for row in observations),
                   'original_namespace_equals_artifact_name': sum(row['original_namespace_equals_artifact_name']
                                                                 for row in observations)},
        'payload_error_counts': dict(Counter(row['observed_payload'].get('error_type') for row in observations)),
        'rows': rows,
        'conclusion': 'The earlier diagnostic joined only original GAVs. All twelve libraries exist in stored observations; original Syft namespaces differ, while the existing peer has the expected exact GAV at each unique path/layer. The existing bridge remains blocked by unconfirmed BudgetExceeded payload. No namespace alias or module-path rewrite is warranted.',
        'recommendations': ['Keep the original namespace and producer audit; let the unchanged path/layer peer bridge act only after new physical proof',
                            'Diagnose the bounded rejection guard and compare a separately frozen reader; do not assume every starter has class/resource bytes',
                            'Correct the diagnostic join, not the classifier with expected GAV lists',
                            'Preserve earlier R106 metrics and all unknown scopes; this report alone adds zero TP'],
        'limitations': ['No new physical reads; BudgetExceeded guard origin still not established here',
                        'Same name/version is used only for post-analysis evidence discovery, never as classification proof',
                        'Leading slash normalization is the existing peer path convention, not an alias or owner guess',
                        'Some metadata-only starter artifacts may remain UNKNOWN even if the budget rejection is removed']}
    atomic_json(OUTPUT / 'report.json', report)
    print(json.dumps(report['counts']))


if __name__ == '__main__':
    main()

"""Retain raw cross-platform observation differences beside selected-output parity.

This reads completed scanner outputs only. It cannot scan, access build references,
or explain a producer difference from counts alone.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from run import ROOT, atomic_json
from verify_mvp_r110_container import read, sha


def fingerprint(artifact):
    return json.dumps({key: artifact.get(key) for key in (
        'type', 'foundBy', 'purl', 'name', 'version')}, sort_keys=True, separators=(',', ':'))


def main():
    output = ROOT / 'benchmarks/results/mvp-r110-container-v1'
    destination = output / 'raw-observation-audit.json'
    if destination.exists():
        raise FileExistsError('Preserve completed raw-observation audit')
    parity = read(output / 'parity.json')
    if parity.get('reference_accessed') is not False:
        raise ValueError('Completed no-oracle prediction parity is required')
    folders = {'linux': output / 'rest/workspace/analysis',
               'windows': ROOT / 'benchmarks/results/mvp-r110-held-controls-v1/rest/analysis'}
    rows, documents = {}, {}
    inputs = {}
    for platform, folder in folders.items():
        path = folder / 'image-original.syft.json'
        document, summary = read(path), read(folder / 'summary.json')
        observed = Counter(fingerprint(artifact) for artifact in document['artifacts'])
        documents[platform] = document
        rows[platform] = {'raw_scanner_artifacts': len(document['artifacts']),
                          'selected_artifacts': summary['selected_count'],
                          'final_os_full': [summary[key] for key in ('final_count', 'os_count', 'full_count')],
                          'unknown_decision_groups': summary['decisions']['UNKNOWN'],
                          'unknown_reasons': summary['unknown_reasons'],
                          'cataloger_counts': dict(Counter(artifact.get('foundBy') for artifact in document['artifacts'])),
                          'raw_coordinate_fingerprints': observed}
        inputs[platform] = {name: sha(folder / name) for name in (
            'image-original.syft.json', 'summary.json', 'review.json', 'selected.syft.json')}
    left, right = [rows[name]['raw_coordinate_fingerprints'] for name in ('linux', 'windows')]
    left_only, right_only = left - right, right - left
    for row in rows.values():
        del row['raw_coordinate_fingerprints']
    def detail(document, differences):
        return [{key: artifact.get(key) for key in (
            'id', 'type', 'foundBy', 'purl', 'name', 'version', 'locations')}
            for artifact in document['artifacts'] if fingerprint(artifact) in differences]
    result = {'status': 'RECORDED_RAW_DIFFERENCES', 'reference_accessed': False,
        'fresh_scans_performed_by_this_audit': False, 'predictions_or_parity_modified': False,
        'rows': rows,
        'raw_identity_fingerprint_multiset_equal': left == right,
        'linux_only_raw_fingerprints': list(left_only.elements()),
        'windows_only_raw_fingerprints': list(right_only.elements()),
        'linux_only_raw_observations': detail(documents['linux'], left_only),
        'windows_only_raw_observations': detail(documents['windows'], right_only),
        'selected_component_coordinate_parity': {key: value['coordinate_multisets_equal']
                                                for key, value in parity['views'].items()},
        'selected_os_artifact_ids_equal': parity['selected_artifact_ids_equal'],
        'non_os_selected_artifact_ids_equal': parity['non_os_selected_artifact_ids_equal'],
        'cause': 'UNKNOWN; no attribution from counts or repeated scans',
        'inputs': inputs, 'parity_sha256': sha(output / 'parity.json'),
        'audit_script_sha256': sha(Path(__file__)),
        'scope': 'Raw package observation parity is separate from delivered-component coordinate parity and accuracy'}
    (output / 'executed-raw-observation-audit.py').write_bytes(Path(__file__).read_bytes())
    atomic_json(destination, result)
    print(json.dumps({'rows': rows, 'linux_only_raw': len(list(left_only.elements())),
                      'windows_only_raw': len(list(right_only.elements()))}))


if __name__ == '__main__':
    main()

"""Post-prediction installed/Windows parity, without any reference SBOM input."""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path

from replay_js_publish_r107 import coordinates, selected_ids
from run import ROOT, atomic_json

sys.path.insert(0, str(ROOT / 'src'))

from sbom_creator.validation import validate_cyclonedx


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def main():
    output = ROOT / 'benchmarks/results/mvp-r109-container-v1'
    destination = output / 'parity.json'
    if destination.exists():
        raise FileExistsError('Keep every completed parity attempt')
    linux = output / 'nest/workspace/analysis'
    windows = ROOT / 'benchmarks/results/mvp-js-types-r109-v1/paired-nest-starter-v1/analysis'
    marker = read(ROOT / 'benchmarks/results/mvp-js-types-r109-v1/predictions-complete.json')
    if marker.get('oracle_read') is not False:
        raise ValueError('Prediction isolation marker missing')
    verification = read(output / 'verification.json')
    if (verification['exit_code'] != 0
            or not verification['installed_source_and_data_equal_frozen_snapshot']
            or not verification['source_hashes_unchanged_after_prediction']
            or not verification['public_java_db_unchanged']):
        raise ValueError('Installed pipeline verification must pass first')
    artifacts = read(output / 'nest/artifact-manifest.json')
    exported = {}
    for name, entry in artifacts.items():
        stored = (output / 'nest' / entry['file']).read_bytes()
        raw = gzip.decompress(stored) if entry['file'].endswith('.gz') else stored
        if (hashlib.sha256(stored).hexdigest() != entry['stored_sha256']
                or hashlib.sha256(raw).hexdigest() != entry['original_sha256']):
            raise ValueError('Export hash mismatch')
        exported[name] = json.loads(raw)
    views = {}
    for view in ('final', 'os', 'full'):
        filename = view + '.cdx.json'
        left, right = read(linux / filename), read(windows / filename)
        validate_cyclonedx(left)
        validate_cyclonedx(right)
        left_coords, right_coords = coordinates(left), coordinates(right)
        equal = left_coords == right_coords
        if view == 'final' and not equal:
            raise ValueError('Cross-platform non-OS final component-coordinate multiset mismatch')
        if left != exported[filename]:
            raise ValueError('Published/exported document mismatch')
        views[view] = {'coordinate_multisets_equal': equal,
                      'components': len(left.get('components', [])), 'schema_valid': True,
                      'windows_components': len(right.get('components', [])),
                      'linux_only': list((left_coords - right_coords).elements()),
                      'windows_only': list((right_coords - left_coords).elements()),
                      'linux_sha256': sha(linux / filename), 'windows_sha256': sha(windows / filename)}
    selected = [read(folder / 'selected.syft.json') for folder in (linux, windows)]
    left_ids, right_ids = [selected_ids(document) for document in selected]
    os_types = {'apk', 'deb', 'rpm', 'alpm', 'portage', 'nix', 'opkg'}
    non_os_ids = [sorted(a['id'] for a in document['artifacts'] if a.get('type') not in os_types)
                  for document in selected]
    if non_os_ids[0] != non_os_ids[1]:
        raise ValueError('Cross-platform non-OS selected artifact IDs differ')
    facts = []
    for folder in (linux, windows):
        provenance = read(folder / 'provenance.json')
        values = {aid: fact for aid, fact in provenance['image']['payload_evidence'].items()
                  if fact.get('payload_kind') == 'declared_type_surface'}
        facts.append(values)
    if facts[0] != facts[1] or not facts[0]:
        raise ValueError('Declared-type physical observation differs or is absent')
    all_views_equal = all(view['coordinate_multisets_equal'] for view in views.values())
    status = 'passed' if all_views_equal and left_ids == right_ids else 'PARTIAL_CROSS_PLATFORM_PARITY'
    atomic_json(destination, {'status': status, 'reference_accessed': False,
        'mode': 'actual installed Linux and fresh Windows image-only prediction parity',
        'new_accuracy_measurement': False, 'views': views,
        'selected_artifact_ids_equal': left_ids == right_ids,
        'selected_artifact_id_difference': {'linux_only': sorted(set(left_ids) - set(right_ids)),
                                           'windows_only': sorted(set(right_ids) - set(left_ids))},
        'non_os_selected_artifact_ids_equal': True, 'non_os_selected_count': len(non_os_ids[0]),
        'selected_artifact_count': len(left_ids), 'declared_type_witnesses_equal': True,
        'declared_type_witnesses': facts[0], 'verified_exported_artifacts': len(exported),
        'public_java_database': 'read-only mounted by shared harness; no Java archive analysis in this Node image',
        'installed_hashes_verified': verification['installed_file_count'],
        'image_id': verification['image_id'], 'verifier_sha256': sha(Path(__file__)),
        'inputs': {'windows_marker_sha256': sha(ROOT / 'benchmarks/results/mvp-js-types-r109-v1/predictions-complete.json'),
                   'installed_verification_sha256': sha(output / 'verification.json'),
                   'export_manifest_sha256': sha(output / 'nest/artifact-manifest.json')}})
    print(json.dumps({'status': status, 'views': {k: v['components'] for k, v in views.items()},
                      'selected_ids': len(left_ids), 'type_witnesses': len(facts[0])}))


if __name__ == '__main__':
    main()

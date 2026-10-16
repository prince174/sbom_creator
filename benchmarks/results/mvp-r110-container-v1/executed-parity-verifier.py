"""Post-prediction REST Windows/installed parity, without reference SBOM access."""
from __future__ import annotations

import argparse
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
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-output', type=Path,
                        default=ROOT / 'benchmarks/results/mvp-r110-held-controls-v1')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'benchmarks/results/mvp-r110-container-v1')
    args = parser.parse_args()
    output, parent = args.output.resolve(), args.parent_output.resolve()
    destination = output / 'parity.json'
    if destination.exists():
        raise FileExistsError('Keep every completed parity attempt')
    marker = read(parent / 'predictions-complete.json')
    if marker.get('oracle_read') is not False:
        raise ValueError('Parent completed-prediction isolation marker is required')
    verification = read(output / 'verification.json')
    if (verification.get('status') != 'passed' or verification.get('exit_code') != 0
            or verification.get('installed_file_count') != 47
            or any(verification.get(key) is not True for key in (
                'installed_source_and_data_equal_frozen_snapshot',
                'source_hashes_unchanged_after_prediction', 'public_java_db_unchanged',
                'default_java_archive_components_true_nested_windows_false',
                'docker_env_reader_overrides_absent'))):
        raise ValueError('Installed default-config pipeline verification must pass first')
    freeze = read(output / 'candidate-freeze.json')
    if sha(parent / 'freeze.json') != freeze['parent_freeze_sha256']:
        raise ValueError('Parent frozen candidate differs from installed build input')
    linux = output / 'rest/workspace/analysis'
    windows = parent / 'rest/analysis'
    run = read(parent / 'rest/run.json')
    if run.get('oracle_read') is not False:
        raise ValueError('Windows REST invocation did not retain no-oracle provenance')
    artifacts = read(output / 'rest/artifact-manifest.json')
    exported = {}
    for name, entry in artifacts.items():
        stored = (output / 'rest' / entry['file']).read_bytes()
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
        if left != exported[filename]:
            raise ValueError('Installed/exported SBOM differs')
        left_coords, right_coords = coordinates(left), coordinates(right)
        equal = left_coords == right_coords
        if view == 'final' and not equal:
            raise ValueError('Installed non-OS delivered-component coordinate multiset differs')
        views[view] = {'coordinate_multisets_equal': equal, 'schema_valid': True,
                      'linux_components': len(left.get('components', [])),
                      'windows_components': len(right.get('components', [])),
                      'linux_only': list((left_coords - right_coords).elements()),
                      'windows_only': list((right_coords - left_coords).elements()),
                      'linux_sha256': sha(linux / filename), 'windows_sha256': sha(windows / filename)}
    selected = [read(folder / 'selected.syft.json') for folder in (linux, windows)]
    left_ids, right_ids = [selected_ids(document) for document in selected]
    os_types = {'apk', 'deb', 'rpm', 'alpm', 'portage', 'nix', 'opkg'}
    non_os_ids = [sorted(artifact['id'] for artifact in document['artifacts']
                         if artifact.get('type') not in os_types) for document in selected]
    if non_os_ids[0] != non_os_ids[1]:
        raise ValueError('Installed non-OS selected artifact IDs differ')
    provenance = [read(folder / 'provenance.json') for folder in (linux, windows)]
    config_ids = [item['image'].get('image_config_digest') for item in provenance]
    if not config_ids[0] or config_ids[0] != config_ids[1]:
        raise ValueError('Installed and Windows predictions are bound to different input image configs')
    if any(item.get('source_kind') != 'not-provided' for item in provenance):
        raise ValueError('Image-only parity cannot silently consume source input')
    payloads = [item['image'].get('payload_evidence') for item in provenance]
    proofs = [item['image'].get('identity_binding_envelope', {}).get('archive_presence', {})
              for item in provenance]
    if payloads[0] is None or payloads[0] != payloads[1] or proofs[0] != proofs[1]:
        raise ValueError('Installed observed payload/archive presence facts differ')
    summaries = [read(folder / 'summary.json') for folder in (linux, windows)]
    if any(summary.get('policy_version') != 'image-delivered-archive-v7' for summary in summaries):
        raise ValueError('Default-config Java must select the existing v7 policy')
    all_views_equal = all(value['coordinate_multisets_equal'] for value in views.values())
    status = 'passed' if all_views_equal and left_ids == right_ids else 'PARTIAL_CROSS_PLATFORM_PARITY'
    (output / 'executed-parity-verifier.py').write_bytes(Path(__file__).read_bytes())
    atomic_json(destination, {'status': status, 'reference_accessed': False,
        'mode': 'actual installed default-config REST versus completed Windows R110 image-only prediction',
        'new_accuracy_measurement': False, 'views': views,
        'selected_artifact_ids_equal': left_ids == right_ids,
        'selected_artifact_id_difference': {'linux_only': sorted(set(left_ids) - set(right_ids)),
                                           'windows_only': sorted(set(right_ids) - set(left_ids))},
        'non_os_selected_artifact_ids_equal': True, 'non_os_selected_count': len(non_os_ids[0]),
        'observed_payload_facts_equal': True, 'archive_presence_facts_equal': True,
        'complete_archive_proof_instances': len(proofs[0]), 'installed_hashes_verified': 47,
        'reader_defaults_used_without_environment_overrides': True,
        'java_archive_components_default': True, 'java_nested_windows_default': False,
        'java_policy_version': 'image-delivered-archive-v7',
        'image_config_digest': config_ids[0], 'installed_image_id': verification['image_id'],
        'verifier_sha256': sha(Path(__file__)), 'verified_exported_artifacts': len(exported),
        'inputs': {'windows_marker_sha256': sha(parent / 'predictions-complete.json'),
                   'installed_verification_sha256': sha(output / 'verification.json'),
                   'export_manifest_sha256': sha(output / 'rest/artifact-manifest.json')},
        'limitations': ['Local archive acquisition excludes registry download and cold public DB download',
                       'Partial OS/full differences, if any, remain explicit and are never filtered for parity',
                       'No process RSS, hard-quota, concurrency or universal accuracy claim']})
    print(json.dumps({'status': status, 'non_os_selected': len(non_os_ids[0]),
                      'archive_proofs': len(proofs[0]), 'views': {
                          key: value['linux_components'] for key, value in views.items()}}))


if __name__ == '__main__':
    main()

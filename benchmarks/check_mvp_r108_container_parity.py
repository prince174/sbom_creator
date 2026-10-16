"""Compare the completed installed Linux output with the frozen Windows run."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT/'benchmarks/results/mvp-r108-container-v1'
LINUX = OUTPUT/'microservices/workspace/analysis'
WINDOWS = ROOT/'benchmarks/results/mvp-r108-v1/java/microservices/analysis'


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def coordinates(document):
    return Counter(tuple(c.get(key) for key in ('type', 'group', 'name', 'version', 'purl'))
                   for c in document.get('components', []))


def main():
    freeze = read(OUTPUT/'candidate-freeze.json')
    verification = read(OUTPUT/'verification.json')
    environment = read(OUTPUT/'microservices/workspace/environment.json')
    expected = {key.removeprefix('src/sbom_creator/'): value
                for key, value in freeze['source_hashes'].items() if key.startswith('src/sbom_creator/')}
    assert len(expected) == 47 and environment['installed_source_hashes'] == expected
    assert verification['exit_code'] == 0
    assert environment['java_nested_windows'] is True and environment['java_archive_components'] is True
    linux_provenance, windows_provenance = read(LINUX/'provenance.json'), read(WINDOWS/'provenance.json')
    assert linux_provenance['image']['image_config_digest'] == windows_provenance['image']['image_config_digest']
    report = {'comparison': 'Installed Linux vs cached-input Windows R108; same frozen source/image, whole views',
              'reference_accessed': False, 'views': {}, 'installed_source_files': len(expected),
              'installed_sources_equal_freeze': True,
              'java_nested_windows_effective': environment['java_nested_windows'],
              'java_archive_components_effective': environment['java_archive_components'],
              'image_config_digest': linux_provenance['image']['image_config_digest'],
              'schema_data_sha256': {key: value for key, value in expected.items() if key.startswith('schemas/')}}
    for filename in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
        left, right = coordinates(read(LINUX/filename)), coordinates(read(WINDOWS/filename))
        report['views'][filename] = {'equal_coordinate_multisets': left == right,
            'linux_components': left.total(), 'windows_components': right.total(),
            'linux_only': [list(key)+[value] for key, value in (left-right).items()],
            'windows_only': [list(key)+[value] for key, value in (right-left).items()],
            'linux_file_sha256': sha(LINUX/filename), 'windows_file_sha256': sha(WINDOWS/filename)}
    left, right = (Counter(a['id'] for a in read(path/'selected.syft.json')['artifacts'])
                   for path in (LINUX, WINDOWS))
    report['selected_artifact_ids'] = {'equal': left == right, 'linux_count': left.total(),
        'windows_count': right.total(), 'linux_only': list((left-right).elements()),
        'windows_only': list((right-left).elements())}
    linux_audit, windows_audit = (read(path/'image-identity-audit.json') for path in (LINUX, WINDOWS))
    linux_proofs, windows_proofs = (document['binding']['archive_components']
                                    for document in (linux_audit, windows_audit))
    bound = [item for item in linux_proofs if item.get('status') == 'BOUND_ARCHIVE_COMPONENT']
    payload = linux_provenance['image']['payload_evidence']
    database_sha256 = freeze['inputs']['public_java_db']['sha256']
    for item in bound:
        proof = item['archive_presence']
        assert proof['image_config_digest'] == report['image_config_digest']
        assert proof['chain_verified'] is True and proof['zip_crc_verified'] is True
        assert len(proof['sha256']) == 64 and len(proof['sha1']) == 40
        association = proof.get('public_hash_association')
        if association:
            assert association['database_sha256'] == database_sha256
            assert association['sha1'] == proof['sha1']
            assert association['purl'] == proof['identity']
        assert payload[item['artifact_id']]['status'] == 'unconfirmed'
    report['archive_component_evidence'] = {
        'bound_complete_archive_proofs': len(bound),
        'identity_methods': dict(Counter(item['archive_presence']['identity_method'] for item in bound)),
        'all_original_payload_facts_still_unconfirmed': True,
        'all_payload_facts_equal_windows': payload == windows_provenance['image']['payload_evidence'],
        'proofs_equal_windows': {row['artifact_id']: row for row in linux_proofs}
                               == {row['artifact_id']: row for row in windows_proofs},
        'public_database_sha256': database_sha256,
        'database_binding_equal_windows': linux_audit['binding']['archive_identity_database']
                                          == windows_audit['binding']['archive_identity_database']}
    report['physical_read_resources'] = {key: linux_audit[key] for key in ('jar_resources', 'layer_resources')}
    (OUTPUT/'windows-coordinate-comparison.json').write_text(json.dumps(report, indent=2)+'\n')
    assert all(value['equal_coordinate_multisets'] for value in report['views'].values()), report['views']
    assert report['selected_artifact_ids']['equal'], report['selected_artifact_ids']
    assert report['archive_component_evidence']['all_payload_facts_equal_windows']
    assert report['archive_component_evidence']['proofs_equal_windows']
    assert report['archive_component_evidence']['database_binding_equal_windows']
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

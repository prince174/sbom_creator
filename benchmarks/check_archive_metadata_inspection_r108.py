"""Verify the completed physical inspection without repeating image reads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT/'benchmarks/results/archive-metadata-inspection-r108-v1'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    freeze = json.loads((OUTPUT/'freeze.json').read_text())
    assert freeze['reference_accessed'] is False
    assert sha(OUTPUT/'executed-source/inspect_archive_metadata_r108.py') == freeze['script_sha256']
    for relative, expected in freeze['code_hashes'].items():
        assert sha(OUTPUT/'executed-source'/relative) == expected, relative
    reports, rows, complete_bytes = {}, [], 0
    for case, inputs in freeze['input_hashes'].items():
        for relative, expected in inputs.items():
            assert sha(ROOT/relative) == expected, relative
        provenance_path = next(p for p in inputs if p.endswith('/provenance.json'))
        prior = json.loads((ROOT/provenance_path).read_text())['image']['payload_evidence']
        report = json.loads((OUTPUT/f'{case}.json').read_text())
        observations = report['observations']
        assert report['reference_accessed'] is False and report['classifier_changed'] is False
        assert report['candidates'] == len(observations)
        assert report['candidates'] <= 4096
        stats = report['jar_resources']
        assert stats['class_witnesses'] == stats['resource_witnesses'] == 0
        assert stats['verification_read_bytes'] <= 8*1024**3
        assert stats['index_bytes'] <= 16*1024**2 and stats['zip_entries'] <= 100_000
        for row in observations:
            assert row['classification_changed'] is False
            assert row['prior_payload_fact'] == prior.get(row['artifact_id'])
            assert (row['prior_payload_fact'] or {}).get('status') != 'confirmed'
            if row['status'] == 'inspected':
                assert row['inspection']['captured_raw_name_and_metadata_bytes'] <= 32*1024
                assert row['inspection']['class_entry_count'] == 0
                digest = row['whole_jar_digests']
                assert digest['status'] == 'complete'
                assert len(digest['sha1']) == 40 and len(digest['sha256']) == 64
                assert digest['physical_range']['bytes'] == digest['bytes']
                complete_bytes += digest['bytes']
                rows.append(row)
        reports[case] = {key: report[key] for key in ('candidates', 'status_counts', 'classless_observations')}
    assert complete_bytes <= 32*1024**2
    index = json.loads((OUTPUT/'digest-index.json').read_text())
    assert index['unique_physical_content'] == len(index['rows'])
    assert {row['sha256'] for row in index['rows']} == {row['whole_jar_digests']['sha256'] for row in rows}
    result = {'status': 'PASS', 'frozen_source_snapshots': len(freeze['code_hashes']),
              'input_hashes_verified': sum(len(v) for v in freeze['input_hashes'].values()),
              'reports': reports, 'complete_digest_observations': len(rows),
              'complete_digest_read_bytes': complete_bytes,
              'unique_physical_content': index['unique_physical_content'],
              'independent_stored_sha256_crc_rechecks': sum(
                  row['whole_jar_digests']['parent_stored_crc_and_sha256_rechecked'] for row in rows),
              'prior_runtime_facts_unchanged': True, 'reference_accessed': False,
              'reader_rescan': False}
    (OUTPUT/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

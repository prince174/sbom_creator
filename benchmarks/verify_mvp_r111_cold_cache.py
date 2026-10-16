"""Post-run receipt/schema/export checks; no source repository, oracle or network."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

from check_mvp_r111_cold_cache import coordinates, sha, write

from sbom_creator.validation import validate_cyclonedx

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PREFLIGHT = {
    'existing-symlink-cache-root', 'existing-symlink-java-db', 'existing-symlink-trivy-java.db',
    'existing-symlink-metadata.json', 'symlink-ancestor-does-not-create-outside-child',
    'staged-symlink-target-preserved', 'atomic-no-replace-empty', 'atomic-no-replace-nonempty',
    'atomic-positive-toy-cold-warm'}


def program_snapshot(path, expected):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    normalized = hashlib.sha256(raw.replace(b'\r\n', b'\n')).hexdigest()
    assert digest == expected or normalized == expected
    return {'stored_sha256': digest, 'executed_lf_sha256': expected,
            'binding': 'exact' if digest == expected else 'CRLF/LF-only snapshot serialization'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/results/mvp-r111-cold-cache-v2')
    args = parser.parse_args()
    root = args.output.resolve()
    target = root / 'verification.json'
    if target.exists():
        raise FileExistsError('Never overwrite a completed independent verification')
    frozen = json.loads((root / 'candidate-freeze.json').read_bytes())
    report = json.loads((root / 'report.json').read_bytes())
    expected = frozen['installed_expected_source_hashes']
    image = json.loads((root / 'built-image.json').read_bytes())
    assert len(expected) == 48
    for name, digest in expected.items():
        assert sha(root / 'executed-source/sbom_creator' / name) == digest
        assert sha(ROOT / 'src/sbom_creator' / name) == digest
    for name, digest in frozen['source_sha256'].items():
        assert sha(ROOT / name) == digest
    assert sha(root / 'executed-harness.py') == frozen['harness_sha256']
    program_bindings = {
        'pipeline': program_snapshot(root / 'container-program.py', frozen['container_program_sha256']),
        'native_preflight': program_snapshot(root / 'native-preflight-program.py', frozen['preflight_program_sha256'])}
    assert frozen['old_public_database_read_or_mounted'] is False
    assert frozen['network_job_limit'] == 1 and frozen['download_timeout_seconds'] == 600
    assert frozen['reference_accessed'] is False
    preflight = json.loads((root / 'native-preflight/result.json').read_bytes())
    assert set(preflight['cases']) == EXPECTED_PREFLIGHT and len(preflight['cases']) == 9
    assert preflight['skips'] == 0 and preflight['network'] == 'none'
    assert preflight['public_database_read_or_downloaded'] is False
    assert preflight['installed_source_hashes'] == expected
    assert report['status'] == 'passed' and report['network_jobs_started'] == 1
    assert report['network_retry_performed'] is False
    schemas, verified, views, phase_results = 0, 0, {}, {}
    for phase in ('cold', 'warm'):
        folder = root / phase
        phase_report = json.loads((folder / 'run.json').read_bytes())
        result = json.loads((folder / 'result.json').read_bytes())
        environment = json.loads((folder / 'environment.json').read_bytes())
        inspected = json.loads((folder / 'container-inspect.json').read_bytes())
        assert phase_report['status'] == 'passed' and phase_report['exit_code'] == 0
        assert phase_report['image_id'] == image['image_id'] == inspected['image_id']
        assert inspected['network_mode'] == ('bridge' if phase == 'cold' else 'none')
        assert inspected['user'] == '10001:10001' and inspected['read_only_rootfs'] is True
        assert inspected['memory_bytes'] == 3 * 1024**3 and inspected['nano_cpus'] == 2 * 10**9
        assert inspected['cap_drop'] == ['ALL']
        assert 'no-new-privileges' in inspected['security_opt']
        mounts = inspected['mounts']
        assert len(mounts) == 2
        assert any(m['Type'] == 'bind' and m['Destination'] == '/inputs/image.tar' and m['RW'] is False for m in mounts)
        assert any(m['Type'] == 'volume' and m['Name'] == frozen['new_workspace_volume']
                   and m['Destination'] == '/workspace' and m['RW'] is True for m in mounts)
        assert environment['installed_source_hashes'] == expected
        assert environment['java_archive_components_default'] is True
        assert environment['java_nested_windows_default'] is False
        assert environment['reader_environment_overrides_absent'] is True
        assert environment['cache_database_present_before_pipeline'] is (phase == 'warm')
        assert environment['cache_metadata_present_before_pipeline'] is (phase == 'warm')
        engine = result['java_identity_engine']
        assert engine['java_database_cache_status'] == ('published' if phase == 'cold' else 'reused')
        assert (engine['java_database_download_seconds'] > 0) is (phase == 'cold')
        assert engine['database_sha256'] == result['database_sha256']
        assert engine['database_metadata_sha256'] == result['metadata_sha256']
        assert result['vulnerability_database_absent'] is True
        assert result['source_input'] is False and result['reference_accessed'] is False
        assert result['image_config_digest'] == frozen['input']['previously_observed_config_digest']
        manifest = json.loads((folder / 'artifact-manifest.json').read_bytes())
        views[phase] = {}
        for name, entry in manifest.items():
            stored = (folder / entry['file']).read_bytes()
            raw = gzip.decompress(stored)
            assert hashlib.sha256(stored).hexdigest() == entry['stored_sha256']
            assert hashlib.sha256(raw).hexdigest() == entry['original_sha256']
            assert len(raw) == entry['original_bytes']
            document = json.loads(raw)
            verified += 1
            if name in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
                validate_cyclonedx(document)
                schemas += 1
                views[phase][name] = coordinates(document)
        phase_results[phase] = {'pipeline_seconds': result['pipeline_seconds'],
            'download_seconds': engine['java_database_download_seconds'],
            'validation_seconds': engine['java_database_validation_seconds'],
            'database_sha256': result['database_sha256'], 'database_bytes': result['database_bytes'],
            'metadata_sha256': result['metadata_sha256'],
            'component_counts': {name: sum(counts.values()) for name, counts in views[phase].items()}}
    cold, warm = phase_results['cold'], phase_results['warm']
    assert len(views['cold']) == len(views['warm']) == 3
    assert views['cold'] == views['warm']
    assert cold['database_sha256'] == warm['database_sha256']
    assert cold['metadata_sha256'] == warm['metadata_sha256']
    verification = {'status': 'passed', 'installed_source_files_verified': len(expected),
        'native_preflight_cases_passed': 9, 'native_preflight_skips': 0,
        'cyclonedx_schemas_verified': schemas, 'lossless_exports_verified': verified,
        'cold_warm_three_coordinate_multisets_equal': True,
        'program_snapshot_bindings': program_bindings,
        'source_build_and_snapshot_hashes_unchanged': True,
        'image_id': image['image_id'], 'phases': phase_results,
        'reference_accessed': False, 'accuracy_evaluated': False,
        'public_tags_mutable': True, 'publisher_authenticity_proven': False}
    write(target, verification)
    print(json.dumps(verification, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

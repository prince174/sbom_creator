"""Read-only public cache validation costs; no project/reference inputs."""
import hashlib
import importlib.util
import json
import shutil
import sqlite3
import time

from run import ROOT, atomic_json

OUTPUT = ROOT / 'benchmarks/results/public-java-db-validation-r111-v1'
DATABASE = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache/java-db/trivy-java.db'
PIN = 'c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve every validation diagnostic')
    OUTPUT.mkdir()
    shutil.copyfile(__file__, OUTPUT / 'executed-script.py')
    # Assess the immutable pre-bootstrap implementation, not concurrently edited
    # service source. This copied source contains no project/reference data.
    prior = ROOT / 'benchmarks/results/mvp-r110-held-controls-v1/executed-source/sbom_creator/image_java/public_hash_identity.py'
    source = OUTPUT / 'assessed-public-hash-identity.py'
    shutil.copyfile(prior, source)
    spec = importlib.util.spec_from_file_location('assessed_public_lookup', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    metadata_path = DATABASE.with_name('metadata.json')
    metadata_raw = metadata_path.read_bytes()
    started = time.monotonic()
    digest = sha(DATABASE)
    if digest != PIN:
        raise ValueError('Pinned existing public cache changed')
    hash_seconds = time.monotonic() - started
    started = time.monotonic()
    lookup = module.PublicJavaHashLookup(DATABASE, digest)
    init_seconds = time.monotonic() - started
    connection = lookup.connection
    try:
        report = {'read_only': True, 'reference_or_project_inputs': False,
            'database_bytes': DATABASE.stat().st_size, 'database_sha256': digest,
            'assessed_constructor': 'immutable R110 pre-bootstrap implementation',
            'assessed_source_sha256': sha(source),
            'public_metadata': json.loads(metadata_raw),
            'metadata_sha256': hashlib.sha256(metadata_raw).hexdigest(),
            'hash_seconds': hash_seconds, 'constructor_including_rehash_seconds': init_seconds,
            'query_plan': lookup.query_plan,
            'pragmas': {name: connection.execute('PRAGMA ' + name).fetchone()[0] for name in
                ('page_size', 'page_count', 'freelist_count', 'user_version', 'application_id',
                 'encoding', 'journal_mode')},
            'schema_objects': connection.execute(
                'SELECT type,name,tbl_name FROM sqlite_schema ORDER BY type,name LIMIT 32').fetchall(),
            'artifacts_table_info': connection.execute('PRAGMA table_info(artifacts)').fetchall(),
            'indices_index_list': connection.execute('PRAGMA index_list(indices)').fetchall()}
        started = time.monotonic()
        if lookup.lookup('00' * 20) is not None:
            raise ValueError('Structural zero-hash probe unexpectedly resolves')
        report['indexed_missing_hash_seconds'] = time.monotonic() - started
        started = time.monotonic()
        lookup.verify_unchanged()
        report['verify_full_hash_seconds'] = time.monotonic() - started
        callbacks = 0
        started = time.monotonic()

        def guard():
            nonlocal callbacks
            callbacks += 1
            return int(callbacks >= 2000 or time.monotonic() - started > 2)

        connection.set_progress_handler(guard, 1000)
        try:
            report['bounded_quick_check_result'] = connection.execute('PRAGMA quick_check(1)').fetchall()
            report['bounded_quick_check_completed'] = True
        except sqlite3.Error as error:
            report['bounded_quick_check_completed'] = False
            report['bounded_quick_check_error_type'] = type(error).__name__
        finally:
            connection.set_progress_handler(None, 0)
        report.update(bounded_quick_check_seconds=time.monotonic() - started,
            bounded_quick_check_progress_callbacks=callbacks,
            bounded_quick_check_opcode_limit=2_000_000,
            bounded_quick_check_wall_limit_seconds=2,
            quick_check_timeout_does_not_mean_database_corruption=True,
            full_integrity_claimed=False,
            notes=['Warm local-file/cache timing, not cold download/network/storage acceptance',
                   'SQLite progress handler is cooperative and cannot impose a hard blocking-I/O deadline',
                   'Public metadata Version1 is separate from SQLite user_version0',
                   'Full integrity_check/quick_check on each scan is not needed to validate bounded supported schema/index operations',
                   'Exact public SHA1 association is correlated with Trivy and is not publisher authentication'])
    finally:
        lookup.close()
    if sha(DATABASE) != PIN or metadata_path.read_bytes() != metadata_raw:
        raise ValueError('Read-only diagnostic changed its inputs')
    atomic_json(OUTPUT / 'report.json', report)
    atomic_json(OUTPUT / 'input-manifest.json', {'oracle_read': False,
        'script_sha256': sha(OUTPUT / 'executed-script.py'),
        'assessed_source_sha256': sha(source), 'database_sha256': PIN,
        'metadata_sha256': report['metadata_sha256']})
    print(json.dumps({key: report[key] for key in ('hash_seconds',
        'constructor_including_rehash_seconds', 'verify_full_hash_seconds',
        'bounded_quick_check_completed', 'bounded_quick_check_seconds')}))


if __name__ == '__main__':
    main()

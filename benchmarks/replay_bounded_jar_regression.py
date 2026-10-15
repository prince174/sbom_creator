"""Evidence coverage regression on disclosed Javalin; no build oracle read."""
import hashlib
import json
import time
import zipfile

from bounded_jar_evidence import JarFiles
from registry_fixture import archive_config
from run import ROOT, atomic_json


def main():
    work = ROOT / 'benchmarks/.work/paired-javalin-reactor-v1'
    previous = work / 'analysis-metadata-archive-v1'
    output = ROOT / 'benchmarks/results/bounded-javalin-evidence-v2'
    if output.exists():
        raise FileExistsError('Preserve prior attempt')
    document = json.loads((previous / 'image.syft.json').read_bytes())
    config_digest, _ = archive_config(work / 'image.tar')
    assert config_digest == document['source']['metadata']['imageID']
    baseline = json.loads((previous / 'provenance.json').read_bytes())['image']['payload_evidence']
    files = JarFiles(work / 'image.tar', document)
    started = time.monotonic()
    rows = {}
    try:
        for artifact in document['artifacts']:
            if artifact.get('foundBy') != 'java-archive-cataloger':
                continue
            try:
                witness = files.witness(artifact)
                rows[artifact['id']] = {'status': 'confirmed' if witness else 'unconfirmed',
                                        'path': witness, 'error_type': None}
            except (ValueError, KeyError, OSError, RuntimeError, zipfile.BadZipFile) as error:
                files.stats['rejections'] += 1
                rows[artifact['id']] = {'status': 'unconfirmed', 'path': None,
                                        'error_type': type(error).__name__}
    finally:
        files.close()
    lost = [key for key, row in rows.items() if baseline.get(key, {}).get('status') == 'confirmed'
            and row['status'] != 'confirmed']
    gained = [key for key, row in rows.items() if baseline.get(key, {}).get('status') != 'confirmed'
              and row['status'] == 'confirmed']
    report = {'status': 'COVERAGE_REGRESSION' if lost else 'NO_PREVIOUS_WITNESS_LOST',
              'runtime_changed': False, 'oracle_read': False, 'elapsed_seconds': time.monotonic() - started,
              'code_sha256': hashlib.sha256((ROOT / 'benchmarks/bounded_jar_evidence.py').read_bytes()).hexdigest(),
              'previous_confirmed': sum(baseline.get(key, {}).get('status') == 'confirmed' for key in rows),
              'candidate_confirmed': sum(row['status'] == 'confirmed' for row in rows.values()),
              'lost': lost, 'gained': gained, 'artifact_count': len(rows), 'stats': files.stats,
              'limitation': 'Evidence coverage, not component identity accuracy or independent acceptance'}
    atomic_json(output / 'witnesses.json', rows)
    atomic_json(output / 'report.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

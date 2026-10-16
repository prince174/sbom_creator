"""Post-only bootstrap report; compare completed predictions, never classify."""
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

from run import ROOT, atomic_json


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def coordinates(document):
    return Counter(tuple(c.get(k) for k in ('type', 'group', 'name', 'version', 'purl'))
                   for c in document.get('components', []))


def main():
    output = ROOT / 'benchmarks/results/mvp-r111-summary-v1'
    if output.exists():
        raise FileExistsError('Preserve completed summary')
    cold = ROOT / 'benchmarks/results/mvp-r111-cold-cache-v2'
    paths = {name: ROOT / 'benchmarks/results' / value for name, value in {
        'cold_warm': 'mvp-r111-cold-cache-v2/report.json',
        'warm_peer': 'java-db-peer-regression-r111-v1/report.json',
        'prior_accuracy': 'mvp-r110-summary-v1/report.json',
        'prior_dbcp_evaluation': 'mvp-r110-held-controls-v1/evaluation.json'}.items()}
    documents = {key: read(path) for key, path in paths.items()}
    actual = documents['cold_warm']
    if (actual.get('status') != 'passed' or actual.get('network_jobs_started') != 1
            or actual.get('network_retry_performed') is not False):
        raise ValueError('Exactly one successful cold bootstrap and offline warm run required')
    comparisons = {}
    for view in ('final', 'os', 'full'):
        baseline = ROOT / 'benchmarks/results/mvp-r110-held-controls-v1/dbcp/analysis' / (view + '.cdx.json')
        expected = coordinates(read(baseline))
        comparison = {'baseline_sha256': sha(baseline)}
        for phase in ('cold', 'warm'):
            path = cold / phase / 'analysis' / (view + '.cdx.json')
            comparison[phase + '_coordinates_equal_r110'] = coordinates(read(path)) == expected
            comparison[phase + '_sha256'] = sha(path)
            if not comparison[phase + '_coordinates_equal_r110']:
                raise ValueError('DBCP actual delivered component regression differs')
        comparisons[view] = comparison
    phases = {phase: actual[phase]['result'] for phase in ('cold', 'warm')}
    old_hash = 'c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25'
    new_hash = phases['cold']['database_sha256']
    result = {'stage': 'atomic public Java DB bootstrap/reuse',
        'bootstrap_passed': True, 'network_attempts': 1, 'warm_network': 'none',
        'image_id': actual['image_id'],
        'cold_pipeline_seconds': phases['cold']['pipeline_seconds'],
        'warm_pipeline_seconds': phases['warm']['pipeline_seconds'],
        'cold_download_seconds': phases['cold']['java_identity_engine']['java_database_download_seconds'],
        'new_public_database_sha256': new_hash,
        'new_public_database_bytes': phases['cold']['database_bytes'],
        'old_measured_database_sha256': old_hash,
        'new_public_database_differs_from_full_corpus_measured_snapshot': new_hash != old_hash,
        'dbcp_three_views_equal_r110': comparisons,
        'dbcp_known_delivered_score_carried_by_exact_same_bound_image_and_component_sets':
            documents['prior_dbcp_evaluation']['reports']['dbcp']['components'],
        'full_corpus_accuracy_r110': documents['prior_accuracy']['java']['components_micro'],
        'full_corpus_accuracy_remeasured': False,
        'full_corpus_new_database_accuracy_established': False,
        'fresh_oracle_access': False,
        'notes': ['The old measured public DB and immutable image/reference pairs remain unchanged',
            'Peer regression v1 used old frozen DB before final cache-parent-only safety guard',
            'No new Syft/physical/classifier/oracle measurement of the full corpus',
            'Cold latest DB is tested on DBCP only; do not transfer corpus accuracy automatically',
            'Native Linux preflight covers six symlink cases and atomic no-replace visibility',
            'Not power-loss durability, hostile-writer isolation or full SQLite integrity'],
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in paths.values()}}
    output.mkdir()
    shutil.copyfile(__file__, output / 'executed-script.py')
    atomic_json(output / 'report.json', result)
    print(json.dumps({key: result[key] for key in ('bootstrap_passed', 'cold_pipeline_seconds',
          'warm_pipeline_seconds', 'cold_download_seconds', 'new_public_database_sha256')}))


if __name__ == '__main__':
    main()

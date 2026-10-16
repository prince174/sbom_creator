"""Read-only exact public-index associations for prior complete physical digests.

This diagnostic never reads a build reference, runs a scanner, changes a
classifier, or changes accuracy labels. Its inputs are completed independent
physical archive inspections and the already pinned public Trivy Java DB.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path

from public_java_hash_lookup_r108 import DATABASE_SHA256, PublicJavaHashLookup

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / 'benchmarks/results/archive-metadata-inspection-r108-v1'
DATABASE = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache/java-db/trivy-java.db'
SOURCES = [
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy/v0.75.0/go.mod',
     'claim': 'Trivy 0.75.0 pins trivy-java-db v0.0.0-20240109071736-184bd7481d48.'},
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy-java-db/184bd7481d48/pkg/db/db.go',
     'claim': 'SQLite schema v1; SelectIndexBySha1 hex-decodes a complete SHA1 into a BLOB; '
              'unique SHA1 insertion uses ON CONFLICT DO NOTHING; no SHA256 lookup.'},
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy-java-db/184bd7481d48/pkg/types/types.go',
     'claim': 'An index stores GAV, SHA1 bytes and jar/aar archive type.'},
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy-java-db/184bd7481d48/cmd/trivy-java-db/main.go',
     'claim': 'Official CLI has crawl/build commands; no ready exact-hash query command.'},
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy/v0.75.0/pkg/javadb/client.go',
     'claim': 'SearchBySHA1 is exact; SearchByArtifactID has group-count heuristics, excluded here.'},
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy/v0.75.0/pkg/dependency/parser/java/jar/parse.go',
     'claim': 'Parser also accepts embedded POM/manifest or heuristic artifact/version results. '
              'WithChecksum can report a digest independently of identity method; shaded POMs '
              'can share enclosing JAR digest. A peer GAV plus hash does not attest its origin.'},
    {'url': 'https://raw.githubusercontent.com/aquasecurity/trivy/v0.75.0/pkg/fanal/analyzer/language/java/jar/jar.go',
     'claim': 'Image JAR analyzer uses the Java DB and WithChecksum; offline image mode does '
              'not mean absence of local Java DB lookups.'},
    {'url': 'https://github.com/aquasecurity/trivy-java-db',
     'claim': 'Public database associates Maven-index GAV and SHA1; not per-artifact publisher authentication.'},
]


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(path):
    return Path(path).resolve().relative_to(ROOT).as_posix()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', default='public-java-hash-research-r108-v1')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,100}', args.run_id):
        raise ValueError('Bounded result namespace required')
    output = ROOT / 'benchmarks/results' / args.run_id
    output.mkdir(exist_ok=False)
    paths = [INPUT / (case + '.json') for case in ('microservices', 'dropwizard')]
    paths += [INPUT / 'digest-index.json', DATABASE, DATABASE.with_name('metadata.json'),
              Path(__file__), ROOT / 'benchmarks/public_java_hash_lookup_r108.py',
              ROOT / 'src/sbom_creator/image_java/public_hash_identity.py']
    inputs = {relative(path): {'bytes': path.stat().st_size, 'sha256': sha256(path)} for path in paths}
    if inputs[relative(DATABASE)]['sha256'] != DATABASE_SHA256:
        raise ValueError('Public database is not the pinned snapshot')
    write(output / 'freeze.json', {'reference_accessed': False, 'classifier_changed': False,
                                  'inputs': inputs})
    (output / 'executed-source').mkdir()
    for path in (Path(__file__), ROOT / 'benchmarks/public_java_hash_lookup_r108.py'):
        (output / 'executed-source' / path.name).write_bytes(path.read_bytes())

    complete = []
    input_status = {}
    for case in ('microservices', 'dropwizard'):
        document = json.loads((INPUT / (case + '.json')).read_text(encoding='utf-8'))
        if document['reference_accessed'] or document['classifier_changed'] or not document['fresh_physical_reads']:
            raise ValueError('Expected completed physical no-reference diagnostic')
        input_status[case] = document['status_counts']
        for observation in document['observations']:
            if observation['status'] != 'inspected':
                continue
            digests = observation['whole_jar_digests']
            if (digests['status'] != 'complete' or not re.fullmatch('[a-f0-9]{40}', digests['sha1'])
                    or not re.fullmatch('[a-f0-9]{64}', digests['sha256'])
                    or not observation['binding'] or observation['inspection']['class_entry_count'] != 0):
                raise ValueError('Incomplete or non-classless physical evidence')
            complete.append((case, observation))

    digest_index = json.loads((INPUT / 'digest-index.json').read_text(encoding='utf-8'))
    indexed = {row['sha256']: row for row in digest_index['rows']}
    if len(indexed) != digest_index['unique_physical_content']:
        raise ValueError('Duplicate digest index entries')
    by_hash = collections.defaultdict(list)
    for case, observation in complete:
        digests = observation['whole_jar_digests']
        row = indexed[digests['sha256']]
        if (row['sha1'] != digests['sha1'] or row['bytes'] != digests['bytes']
                or not any(item['case'] == case and item['artifact_id'] == observation['artifact_id']
                           and item['binding'] == observation['binding'] for item in row['occurrences'])):
            raise ValueError('Physical inspection and derived digest index disagree')
        by_hash[digests['sha1']].append((case, observation))
    if len({item[1]['whole_jar_digests']['sha256'] for item in complete}) != len(indexed):
        raise ValueError('Incomplete digest index coverage')

    started = time.monotonic()
    unique_counts, observation_counts = collections.Counter(), collections.Counter()
    cases, rows = {}, []
    with PublicJavaHashLookup(DATABASE, DATABASE_SHA256) as lookup:
        schema, plan = lookup.schema, lookup.query_plan
        schema_sql = dict(lookup.connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name"))
        for digest, observations in sorted(by_hash.items()):
            association = lookup.lookup(digest)
            observed_sha256s = {item[1]['whole_jar_digests']['sha256'] for item in observations}
            peer_purls = set().union(*(set(item[1]['peer_observed_purls']) for item in observations))
            status = ('missing_public_association' if association is None else
                      'conflicting_physical_sha256' if len(observed_sha256s) != 1 else
                      'peer_conflict_or_ambiguity' if peer_purls != {association['purl']} else
                      'exact_public_association_and_peer_agreement')
            unique_counts[status] += 1
            occurrences = []
            for case, observation in observations:
                local_status = status
                if association and observation['peer_observed_purls'] != [association['purl']]:
                    local_status = 'peer_conflict_or_ambiguity'
                cases.setdefault(case, collections.Counter())[local_status] += 1
                observation_counts[local_status] += 1
                occurrences.append({
                    'case': case, 'artifact_id': observation['artifact_id'], 'binding': observation['binding'],
                    'original_observed_purl': observation['observed_identity']['purl'],
                    'peer_observed_purls': observation['peer_observed_purls'], 'status': local_status,
                    'stored_crc_sha256_rechecked': observation['whole_jar_digests'][
                        'parent_stored_crc_and_sha256_rechecked'],
                    'original_purl_agrees': association is not None and
                    association['purl'] == observation['observed_identity']['purl'],
                })
            first = observations[0][1]
            rows.append({'sha1': digest, 'sha256': sorted(observed_sha256s),
                         'bytes': first['whole_jar_digests']['bytes'], 'association': association,
                         'status': status, 'class_entry_count': 0,
                         'has_pom_properties': any(item['name'].endswith('/pom.properties')
                                                   for item in first['inspection']['metadata']),
                         'occurrences': occurrences})
    lookup_seconds = round(time.monotonic() - started, 6)
    for path in paths:
        if sha256(path) != inputs[relative(path)]['sha256']:
            raise ValueError('Input changed while querying exact public associations')
    original_mismatches = sum(not occurrence['original_purl_agrees']
                              for row in rows for occurrence in row['occurrences'])
    report = {
        'purpose': 'Read-only public-index association diagnostic, not accuracy evaluation or classifier change',
        'reference_accessed': False, 'project_executed': False, 'network_or_build_cache_used_for_lookup': False,
        'new_physical_reads': False, 'physical_digests': 'Prior fresh complete bound archive reads; not producer digests',
        'input_status_counts': input_status, 'sqlite_version': sqlite3.sqlite_version,
        'database_sha256': DATABASE_SHA256, 'database_bytes': DATABASE.stat().st_size,
        'database_metadata': json.loads(DATABASE.with_name('metadata.json').read_text(encoding='utf-8')),
        'database_schema': schema, 'database_schema_sql': schema_sql, 'query_plan': plan,
        'query_kind': 'Complete SHA1 decoded into binary SQLite BLOB; no prefix/name/version fallback',
        'lookup_seconds_including_one_full_db_pin_check': lookup_seconds,
        'unique_physical_sha1': len(by_hash), 'complete_observations': len(complete),
        'unique_status_counts': dict(unique_counts), 'observation_status_counts': dict(observation_counts),
        'case_observation_counts': {case: dict(values) for case, values in cases.items()},
        'original_producer_purl_disagreements': original_mismatches,
        'original_producer_disagreements_are_retained_not_alias_corrected': True,
        'schema_and_digests_unchanged_after_queries': True,
        'limitations': [
            'DB and Trivy peer share the same identity source and are correlated, not independent evidence engines.',
            'DB SHA1 unique index uses insert-on-conflict-do-nothing; one returned row is not global GAV uniqueness.',
            'Public DB has no SHA256 column/API; independently computed physical SHA256 is retained separately.',
            'SHA1 association and snapshot pin do not authenticate an artifact publisher or defeat chosen collisions.',
            'Zero class entries remain zero: archive presence is not class/resource payload, execution, use or directness.',
            'Uninspected/binding-UNKNOWN observations remain UNKNOWN; this lookup does not clear image/path/layer gates.',
            'No score labels or references were read, changed, filtered, or inferred from the association results.',
        ],
        'official_sources': SOURCES, 'rows': rows,
    }
    write(output / 'report.json', report)
    write(output / 'complete.json', {'report_sha256': sha256(output / 'report.json'),
                                    'freeze_sha256': sha256(output / 'freeze.json'), 'oracle_read': False})
    print(json.dumps({key: report[key] for key in ('unique_physical_sha1', 'complete_observations',
          'unique_status_counts', 'case_observation_counts', 'original_producer_purl_disagreements',
          'lookup_seconds_including_one_full_db_pin_check')}, ensure_ascii=False))


if __name__ == '__main__':
    main()

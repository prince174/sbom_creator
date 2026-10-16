"""Audit existing immutable build hashes for future evaluation-scope closure.

No scanner prediction is consumed and no ground truth or score is modified. This
only measures whether controlled CycloneDX artifact hashes can label delivered
standalone files in the already attested application tree.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import defaultdict
from pathlib import Path

from compare_java_js import all_components, coord
from run import ROOT, atomic_json

OUTPUT = ROOT / 'benchmarks/results/reactor-scope-audit-r107-v1'
PAIRS = ('paired-javalin-reactor-v1', 'paired-dropwizard-reactor-v1',
         'paired-petclinic-microservices-r104')
SHA256 = re.compile('[a-f0-9]{64}')
MAX_JSON = 16 * 1024 * 1024
MAX_ITEMS = 100_000


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    if path.stat().st_size > MAX_JSON:
        raise ValueError('Reference JSON audit budget')
    return json.loads(path.read_bytes())


def component_hash(component):
    values = {item.get('content', '').lower() for item in component.get('hashes', [])
              if item.get('alg') == 'SHA-256'}
    return next(iter(values)) if len(values) == 1 and SHA256.fullmatch(next(iter(values))) else None


def native_set(document):
    pending, result = list(document.get('children', [])), set()
    while pending:
        node = pending.pop()
        result.add(f"pkg:maven/{node['groupId']}/{node['artifactId']}@{node['version']}")
        if len(result) > MAX_ITEMS:
            raise ValueError('Native node count budget')
        pending.extend(node.get('children', []))
    return result


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve the completed scope audit')
    manifest, reports = {}, []
    for name in PAIRS:
        pair = ROOT / 'benchmarks/references' / name
        receipt = read(pair / 'receipt.json')
        if receipt.get('artifact_tree_equal') is not True:
            raise ValueError('Controlled build/final artifact trees were not attested equal')
        for relative, expected in receipt['reference_hashes'].items():
            path = pair / relative
            if sha(path) != expected:
                raise ValueError('Immutable reference changed')
            manifest[path.relative_to(ROOT).as_posix()] = expected
        manifest[(pair / 'receipt.json').relative_to(ROOT).as_posix()] = sha(pair / 'receipt.json')
        labels, tree = read(pair / 'module-labels.json'), read(pair / 'application-tree.json')
        if len(labels) > MAX_ITEMS or len(tree) > MAX_ITEMS:
            raise ValueError('Stored module/tree count budget')
        if len({entry['path'] for entry in tree}) != len(tree):
            raise ValueError('Ambiguous attested application-tree path')
        by_hash, by_module, hash_missing = defaultdict(set), {}, 0
        # Hash identity universe is built solely from controlled per-module CDX.
        for label in labels:
            path = pair / 'modules' / ('root' if label['path'] == '.' else label['path'])
            bom = read(path / 'sbom.json')
            components = all_components(bom)
            owner = coord(bom['metadata']['component'])
            hash_rows = []
            for component in components:
                identity, digest = coord(component), component_hash(component)
                if identity and identity != owner:
                    if digest:
                        by_hash[digest].add(identity)
                        hash_rows.append((identity, digest))
                    else:
                        hash_missing += 1
            by_module[label['path']] = {'bom': bom, 'owner': owner, 'hashes': hash_rows,
                'native': read(path / 'dependency-tree.json')}
        modules = []
        for label in labels:
            if not label.get('image_prefix'):
                continue
            source = by_module[label['path']]
            reference = {coord(component) for component in all_components(source['bom']) if coord(component)} - {source['owner']}
            local_hashes = defaultdict(set)
            for identity, digest in source['hashes']:
                local_hashes[digest].add(identity)
            # A path owner comes from the existing controlled recipe/label, never
            # from a scanner or a package-name heuristic.
            prefix = label['image_prefix'].removeprefix('/application/')
            files = [entry for entry in tree if entry['path'].startswith(prefix)
                     and entry.get('type') == '0' and entry['path'].endswith('.jar')]
            rows = []
            for entry in files:
                digest = entry.get('sha256', '')
                if not SHA256.fullmatch(digest):
                    raise ValueError('Unhashed standalone JAR in attested tree')
                global_choices, local_choices = by_hash.get(digest, set()), local_hashes.get(digest, set())
                primary = label.get('effective_output', {})
                is_primary = primary.get('sha256') == digest
                rows.append({'path': entry['path'], 'sha256': digest,
                    'controlled_module_cdx_gav': sorted(local_choices),
                    'controlled_reactor_cdx_gav': sorted(global_choices),
                    'unique_module_hash_identity': len(local_choices) == 1,
                    'unique_reactor_hash_identity': len(global_choices) == 1,
                    'effective_primary_artifact_hash': is_primary})
            modules.append({'path': label['path'], 'owner': source['owner'],
                'existing_scope': 'NATIVE_CDX_AGREEMENT' if reference == native_set(source['native'])
                                  else 'UNKNOWN_NATIVE_CDX_TRANSITIVE_MISMATCH',
                'build_reference_components': len(reference), 'standalone_jar_files': len(rows),
                'unique_module_hash_matches': sum(row['unique_module_hash_identity'] for row in rows),
                'unique_reactor_hash_matches': sum(row['unique_reactor_hash_identity'] for row in rows),
                'unmatched_standalone_files': [row for row in rows if not row['unique_reactor_hash_identity']],
                'cross_module_only_hash_matches': [row for row in rows if row['unique_reactor_hash_identity']
                                                   and not row['unique_module_hash_identity']],
                'files': rows})
        reports.append({'pair': name, 'commit': receipt['commit'],
            'image_config_digest': receipt['image_binding']['config_digest'],
            'attested_build_final_tree_equal': True, 'cdx_components_without_unique_sha256': hash_missing,
            'distinct_controlled_sha256': len(by_hash),
            'sha256_with_multiple_gav': {digest: sorted(identities) for digest, identities in by_hash.items()
                                       if len(identities) != 1},
            'shipped_modules': len(modules),
            'existing_scope_unknown_modules': sum(row['existing_scope'].startswith('UNKNOWN') for row in modules),
            'modules': modules})
    atomic_json(OUTPUT / 'input-manifest.json', {'post_evaluation_audit_only': True,
        'reference_hashes_verified': manifest, 'script_sha256': sha(Path(__file__)),
        'scanner_prediction_inputs': False})
    shutil.copyfile(__file__, OUTPUT / 'executed-script.py')
    result = {'post_evaluation_audit_only': True, 'scoring_or_truth_modified': False,
        'runtime_classifier_inputs_modified': False, 'new_build_scan_or_image_read': False,
        'reports': reports,
        'conclusion': 'Existing per-module real-build CycloneDX SHA256 hashes and immutable application-tree file SHA256 can support a new independent packaged-artifact label set. Current UNKNOWN scopes and R107 scores are intentionally unchanged.',
        'remaining_proof_work': [
            'Create a separate post-only packaged-artifact label namespace from exact hash matches, with classifier/type-qualified PURLs retained',
            'Revalidate raw controlled build-app.tar/runtime-app.tar against the attested tree and image config binding, without rebuilding',
            'Exclude primary module output only by effective-coordinate/primary-artifact proof; do not guess from filenames',
            'Inventory nested fat-JAR members independently by actual SHA256; current tree labels only standalone files and outer primaries',
            'Keep unidentified packaging-added artifacts, ambiguous shared hashes, build-only artifacts and empty metadata-only delivered JARs explicit',
            'Never derive expected sets from prediction inventories; never supply labels to a predictor',
            'Evaluate new packaged scope separately; do not overwrite existing native/CDX-agreement metrics or claim 31 UNKNOWN resolved now'],
        'limitations': ['Hash-map availability is audited, not a completed independent packaged scope attestation',
                        'A matched component hash does not prove code execution or directness',
                        'No new project recipe or build is needed for the next proof step']}
    atomic_json(OUTPUT / 'report.json', result)
    print(json.dumps([{'pair': row['pair'], 'unknown': row['existing_scope_unknown_modules'],
                       'hash_missing': row['cdx_components_without_unique_sha256'],
                       'collisions': len(row['sha256_with_multiple_gav']),
                       'standalone_files': sum(module['standalone_jar_files'] for module in row['modules']),
                       'module_hash_matches': sum(module['unique_module_hash_matches'] for module in row['modules']),
                       'reactor_hash_matches': sum(module['unique_reactor_hash_matches'] for module in row['modules'])}
                      for row in reports]))


if __name__ == '__main__':
    main()

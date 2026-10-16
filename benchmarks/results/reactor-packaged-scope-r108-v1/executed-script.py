"""Post-only physical binding and standalone SHA256 labels for existing reactors.

No prediction is read when constructing labels. These labels do not close the
scope of nested/shaded content or primary outputs and do not replace historical
native/CycloneDX scope metrics. No build, scanner or source execution is used.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from collections import defaultdict
from pathlib import Path

from audit_reactor_scope_r107 import component_hash
from compare_java_js import all_components, coord
from paired_express import archive_binding
from run import ROOT, atomic_json
from seekable_layer_index import Layers, index

PAIRS = ('paired-javalin-reactor-v1', 'paired-dropwizard-reactor-v1',
         'paired-petclinic-microservices-r104')
OUTPUT = ROOT / 'benchmarks/results/reactor-packaged-scope-r108-v1'
CHUNK = 1024 * 1024
MAX_BYTES = 8 * 1024**3
MAX_JSON = 16 * CHUNK
HEX64 = re.compile('[a-f0-9]{64}')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    if Path(path).stat().st_size > MAX_JSON:
        raise ValueError('Reference JSON budget')
    return json.loads(Path(path).read_bytes())


def tree(entries, stream):
    """Hash every actual regular file, never follow links or extract a path."""
    result, bytes_read = [], 0
    for name, member in sorted(entries.items()):
        if name == '/application':
            if not member.isdir():
                raise ValueError('Application root must be a directory')
            continue
        if not name.startswith('/application/'):
            raise ValueError('Scratch fixture contains unexpected file outside application')
        row = {'path': name.removeprefix('/application/'), 'mode': member.mode,
               'type': member.type.decode('ascii'), 'link': member.linkname}
        if member.isfile():
            if member.size > MAX_BYTES - bytes_read:
                raise ValueError('Post-only aggregate file-hash budget')
            stream.seek(member.offset_data)
            remaining, digest = member.size, hashlib.sha256()
            while remaining:
                block = stream.read(min(CHUNK, remaining))
                if not block:
                    raise ValueError('Truncated delivered artifact')
                digest.update(block)
                remaining -= len(block)
                bytes_read += len(block)
            row['sha256'] = digest.hexdigest()
        result.append(row)
    return result, bytes_read


def exported_tree(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('Post-only TAR file budget')
    with path.open('rb') as stream:
        archive, entries, stats = index(stream, path.stat().st_size)
        with archive:
            result, read_bytes = tree(entries, stream)
    return result, {'tar_index': stats, 'full_file_sha256_read_bytes': read_bytes}


def labels(pair, reference_tree):
    modules = read(pair / 'module-labels.json')
    result = []
    prefixes = [module['image_prefix'] for module in modules if module.get('image_prefix')]
    if len(prefixes) != len(set(prefixes)) or any(not prefix.startswith('/application/')
                                              or not prefix.endswith('/') for prefix in prefixes):
        raise ValueError('Invalid or duplicate controlled owner prefix')
    if any(a.startswith(b) for a in prefixes for b in prefixes if a != b):
        raise ValueError('Overlapping owner prefixes require separate attribution proof')
    for module in modules:
        if not module.get('image_prefix'):
            continue
        bom = read(pair / 'modules' / ('root' if module['path'] == '.' else module['path']) / 'sbom.json')
        owner = coord(bom['metadata']['component'])
        by_hash = defaultdict(set)
        by_hash_raw = defaultdict(set)
        for component in all_components(bom):
            identity, digest = coord(component), component_hash(component)
            if identity and digest and identity != owner:
                by_hash[digest].add(identity)
                by_hash_raw[digest].add(component['purl'])
        prefix = module['image_prefix'].removeprefix('/application/')
        files = [entry for entry in reference_tree if entry['path'].startswith(prefix)
                 and entry['type'] == '0' and entry['path'].endswith('.jar')]
        known, unknown = [], []
        primary = module.get('effective_output', {})
        expected_primary = (prefix + primary['file']) if primary.get('file') else None
        for entry in files:
            digest = entry['sha256']
            if not HEX64.fullmatch(digest):
                raise ValueError('Invalid actual artifact hash')
            choices = by_hash.get(digest, set())
            row = {'image_path': '/application/' + entry['path'], 'sha256': digest}
            if entry['path'] == expected_primary and digest == primary.get('sha256'):
                unknown.append({**row, 'status': 'PRIMARY_OUTPUT_SCOPE_SEPARATE',
                                'effective_owner': owner,
                                'reason': 'Verified primary output; nested/shaded packaging not independently labelled here'})
            elif len(choices) == 1 and len(by_hash_raw[digest]) == 1:
                known.append({**row, 'coordinate': next(iter(choices)),
                              'qualified_purl': next(iter(by_hash_raw[digest])),
                              'status': 'UNIQUE_OWN_MODULE_CDX_SHA256'})
            else:
                unknown.append({**row, 'status': 'UNKNOWN',
                                'module_coordinate_choices': sorted(choices),
                                'module_qualified_purl_choices': sorted(by_hash_raw.get(digest, set())),
                                'reason': 'No unique own-module controlled-build SHA256 identity; no global/filename fallback'})
        expected = {row['coordinate'] for row in known}
        build = {coord(component) for component in all_components(bom) if coord(component)} - {owner}
        result.append({'path': module['path'], 'owner': owner, 'image_prefix': module['image_prefix'],
                       'scope': 'standalone delivered regular JAR file hashes only; primary/nested scope unresolved',
                       'known_file_labels': known, 'unknown_standalone_files': unknown,
                       'known_standalone_coordinate_set': sorted(expected),
                       'build_coordinates_without_confirmed_standalone_file': sorted(build - expected),
                       'complete_image_component_scope_attested': False,
                       'historical_scope_and_metrics_unchanged': True})
    return result


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve previous post-only scope attempt')
    OUTPUT.mkdir()
    shutil.copyfile(__file__, OUTPUT / 'executed-script.py')
    manifests, reports = {}, []
    for name in PAIRS:
        started = time.monotonic()
        pair, work = ROOT / 'benchmarks/references' / name, ROOT / 'benchmarks/.work' / name
        receipt = read(pair / 'receipt.json')
        if receipt.get('artifact_tree_equal') is not True:
            raise ValueError('Original pair does not attest identical build/final trees')
        reference_manifest = {}
        for relative, expected in receipt['reference_hashes'].items():
            path = pair / relative
            if path.resolve().is_relative_to(pair.resolve()) is False or sha(path) != expected:
                raise ValueError('Immutable reference changed or escaped pair')
            reference_manifest[path.relative_to(ROOT).as_posix()] = expected
        reference_manifest[(pair / 'receipt.json').relative_to(ROOT).as_posix()] = sha(pair / 'receipt.json')
        expected_tree = read(pair / 'application-tree.json')
        before, before_stats = exported_tree(work / 'build-app.tar')
        runtime, runtime_stats = exported_tree(work / 'runtime-app.tar')
        if before != expected_tree or runtime != expected_tree:
            raise ValueError('Actual build/runtime exported tree differs from immutable recorded tree')
        expected_binding = receipt['image_binding']
        actual_binding = archive_binding(work / 'image.tar', expected_binding['index_digest'])
        if actual_binding != expected_binding:
            raise ValueError('Actual OCI chain differs from immutable image binding')
        layers = Layers(work / 'image.tar')
        try:
            if layers.config_digest != expected_binding['config_digest'] or len(layers.mapping) != 1:
                raise ValueError('Expected exact scratch fixture config and one application layer')
            diff_id = next(iter(layers.mapping))
            stream, entries = layers.layer(diff_id)
            image_tree, image_read_bytes = tree(entries, stream)
            if image_tree != expected_tree:
                raise ValueError('Actual config-bound image layer tree differs from controlled build bytes')
            layer_stats = dict(layers.stats)
        finally:
            layers.close()
        modules = labels(pair, expected_tree)
        file_manifest = {file.relative_to(ROOT).as_posix(): {'bytes': file.stat().st_size, 'sha256': sha(file)}
                         for file in (work / 'build-app.tar', work / 'runtime-app.tar', work / 'image.tar')}
        manifests[name] = {'reference_hashes': reference_manifest, 'raw_file_hashes': file_manifest}
        report = {'pair': name, 'commit': receipt['commit'], 'actual_oci_binding': actual_binding,
                  'actual_image_diff_id': diff_id,
                  'full_actual_build_runtime_image_trees_equal_recorded_reference': True,
                  'tree_entries': len(expected_tree),
                  'resources': {'build': before_stats, 'runtime': runtime_stats,
                                'actual_image_layer': layer_stats, 'image_file_sha256_read_bytes': image_read_bytes},
                  'seconds': round(time.monotonic() - started, 3), 'modules': modules,
                  'known_standalone_files': sum(len(row['known_file_labels']) for row in modules),
                  'unknown_standalone_files': sum(len(row['unknown_standalone_files']) for row in modules),
                  'complete_image_component_scope_attested': False,
                  'score_not_computed': 'Primary/nested/shaded packaging completeness is not labelled by standalone hashes'}
        reports.append(report)
        atomic_json(OUTPUT / (name + '.json'), report)
        print(name, report['known_standalone_files'], report['unknown_standalone_files'], flush=True)
    atomic_json(OUTPUT / 'input-manifest.json', {'post_only': True, 'oracle_never_passed_to_classifier': True,
        'script_sha256': sha(Path(__file__)), 'dependency_sha256': {str(path.relative_to(ROOT)): sha(path) for path in
        (ROOT / 'benchmarks/seekable_layer_index.py', ROOT / 'benchmarks/paired_express.py',
         ROOT / 'benchmarks/audit_reactor_scope_r107.py')}, 'pairs': manifests})
    atomic_json(OUTPUT / 'report.json', {'post_only': True, 'historical_scores_or_scopes_changed': False,
        'new_scans_builds_classifier_input_changes': False,
        'actual_tree_and_oci_bindings_verified': True, 'reports': reports,
        'remaining_scope_proof': ['Enumerate and SHA256-label nested JAR content independently of predictions',
            'Treat actual primary outputs as separate owners; Javalin lacks recorded primary SHA256/effective_output fields',
            'Keep packaging-added or conflicting qualified PURLs UNKNOWN; do not select truth by prediction intersection',
            'Only then publish a separate complete packaged scope and compare frozen finals; historical metrics stay immutable']})


if __name__ == '__main__':
    main()

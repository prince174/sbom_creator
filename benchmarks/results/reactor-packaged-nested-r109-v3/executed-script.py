"""POST-ONLY SHA256 labels for actual delivered reactor archive contents.

Inputs are controlled build references and independently image-bound TAR bytes.
No prediction, scanner inventory, classifier audit or expected metric is read.
Nested complete-file hashes can establish identities; shaded entry names cannot.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import stat
import tempfile
import time
import zipfile
from collections import defaultdict
from pathlib import Path

from audit_reactor_scope_r107 import component_hash
from bounded_jar_evidence import BudgetExceeded, safe_member, zip_index
from compare_java_js import all_components, coord
from label_reactor_packaged_scope_r108 import PAIRS, exported_tree, read, sha, tree
from paired_express import archive_binding
from run import ROOT, atomic_json
from seekable_layer_index import Layers, index

OUTPUT = ROOT / 'benchmarks/results/reactor-packaged-nested-r109-v3'
PRIOR = ROOT / 'benchmarks/results/reactor-packaged-scope-r108-v1'
CHUNK = 1024 * 1024
MAX_READ = 8 * 1024**3
MAX_FILE = 128 * CHUNK
MAX_NESTED = 32 * CHUNK
MAX_ENTRIES = 2_000_000
MAX_DIRECTORY = 128 * CHUNK
MAX_RATIO = 200
MAX_DEPTH = 8


def rejection_reason(error):
    if isinstance(error, BudgetExceeded):
        return 'ZIP_DIRECTORY_SINGLE_BUDGET'
    if isinstance(error, zipfile.BadZipFile):
        return 'INVALID_ZIP_CRC_OR_STRUCTURE'
    text = str(error)
    return text if text in {'POST_ARCHIVE_SIZE_DEPTH_BUDGET', 'POST_DIRECTORY_AGGREGATE_BUDGET',
        'DUPLICATE_ZIP_MEMBER', 'UNSAFE_ZIP_MEMBER', 'POST_MEMBER_SIZE_INFLATE_BUDGET',
        'DIRECTORY_HAS_PAYLOAD', 'POST_MEMBER_READ_BUDGET', 'TRUNCATED_ZIP_MEMBER',
        'ZIP_MEMBER_SIZE_MISMATCH', 'Missing ZIP directory',
        'Multidisk or ZIP64 unsupported', 'Inconsistent ZIP directory'} else 'UNSUPPORTED_ZIP_STRUCTURE'


def identity_index(components):
    """Retain qualified identities too: an equal GAV count is insufficient."""
    result = defaultdict(lambda: {'coordinates': set(), 'qualified_purls': set()})
    for component in components:
        digest, identity = component_hash(component), coord(component)
        if digest and identity:
            result[digest]['coordinates'].add(identity)
            result[digest]['qualified_purls'].add(component['purl'])
    return result


def unique_identity(digest, own, global_index):
    local, global_value = own.get(digest), global_index.get(digest)
    # Global observed conflicts are retained even if one local context is unique.
    if global_value and (len(global_value['coordinates']) != 1 or
                         len(global_value['qualified_purls']) != 1):
        return None, 'CONFLICTING_GLOBAL_CONTROLLED_HASH_IDENTITIES'
    for value, status in ((local, 'UNIQUE_OWN_MODULE_CDX_SHA256'),
                          (global_value, 'UNIQUE_GLOBAL_REACTOR_CDX_SHA256')):
        if value and len(value['coordinates']) == len(value['qualified_purls']) == 1:
            return {'coordinate': next(iter(value['coordinates'])),
                    'qualified_purl': next(iter(value['qualified_purls'])),
                    'identity_status': status}, None
    return None, 'NO_UNIQUE_CONTROLLED_CDX_SHA256_IDENTITY'


class ArchiveInventory:
    """Bound every decompressed entry read; never extract member paths."""
    def __init__(self):
        self.stats = {'member_read_bytes': 0, 'directory_bytes': 0,
                      'parsed_entries': 0, 'unique_archives': 0,
                      'content_reuses': 0, 'nested_archive_instances': 0}
        self.archives = {}

    def consume(self, source, size, output=None):
        if size < 0 or size > MAX_FILE or size > MAX_READ - self.stats['member_read_bytes']:
            raise ValueError('POST_MEMBER_READ_BUDGET')
        digest, remaining = hashlib.sha256(), size
        while remaining:
            data = source.read(min(CHUNK, remaining))
            if not data:
                raise ValueError('TRUNCATED_ZIP_MEMBER')
            digest.update(data)
            if output is not None:
                output.write(data)
            remaining -= len(data)
            self.stats['member_read_bytes'] += len(data)
        if source.read(1):
            raise ValueError('ZIP_MEMBER_SIZE_MISMATCH')
        return digest.hexdigest()

    def inspect(self, stream, digest, size, depth=0):
        if depth > MAX_DEPTH or size <= 0 or size > (MAX_FILE if depth == 0 else MAX_NESTED):
            raise ValueError('POST_ARCHIVE_SIZE_DEPTH_BUDGET')
        if digest in self.archives:
            self.stats['content_reuses'] += 1
            return self.archives[digest]
        entries, directory_bytes = zip_index(stream)  # before ZipFile allocation
        if (entries > MAX_ENTRIES - self.stats['parsed_entries'] or
                directory_bytes > MAX_DIRECTORY - self.stats['directory_bytes']):
            raise ValueError('POST_DIRECTORY_AGGREGATE_BUDGET')
        self.stats['parsed_entries'] += entries
        self.stats['directory_bytes'] += directory_bytes
        records, nested = [], []
        with zipfile.ZipFile(stream) as archive:
            items = archive.infolist()
            if len(items) != entries or len({item.filename for item in items}) != len(items):
                raise ValueError('DUPLICATE_ZIP_MEMBER')
            if any(not safe_member(item) or
                   (stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    and not (item.is_dir() and item.file_size == 0))
                   for item in items):
                raise ValueError('UNSAFE_ZIP_MEMBER')
            for member in items:
                if (member.file_size > (MAX_NESTED if member.filename.lower().endswith('.jar') else MAX_FILE)
                        or member.file_size > max(1, member.compress_size) * MAX_RATIO):
                    raise ValueError('POST_MEMBER_SIZE_INFLATE_BUDGET')
                row = {'path': member.filename, 'bytes': member.file_size,
                       'crc32': f'{member.CRC:08x}', 'directory': member.is_dir()}
                if member.is_dir():
                    if member.file_size:
                        raise ValueError('DIRECTORY_HAS_PAYLOAD')
                    records.append(row)
                    continue
                if member.filename.lower().endswith('.jar'):
                    # TemporaryFile avoids a large all-in-memory archive allocation.
                    with tempfile.TemporaryFile() as spool:
                        with archive.open(member) as source:
                            row['sha256'] = self.consume(source, member.file_size, spool)
                        row['entry_crc_verified'] = True
                        spool.seek(0)
                        try:
                            child = self.inspect(spool, row['sha256'], member.file_size, depth + 1)
                            child_status, reason = 'COMPLETE_BOUNDED_ZIP_INVENTORY', None
                        except (ValueError, zipfile.BadZipFile, NotImplementedError) as error:
                            child, child_status, reason = {}, 'UNKNOWN_NESTED_CONTENT', rejection_reason(error)
                        nested.append({'path': member.filename, 'sha256': row['sha256'],
                                       'bytes': member.file_size, 'entry_crc_verified': True,
                                       'inventory_sha256': child.get('inventory_sha256'),
                                       'inspection_status': child_status, 'inspection_reason': reason})
                        self.stats['nested_archive_instances'] += 1
                else:
                    with archive.open(member) as source:
                        row['sha256'] = self.consume(source, member.file_size)
                    row['entry_crc_verified'] = True
                records.append(row)
        raw = json.dumps(records, sort_keys=True, separators=(',', ':')).encode()
        result = {'sha256': digest, 'bytes': size, 'entry_count': len(records),
                  'inventory_sha256': hashlib.sha256(raw).hexdigest(),
                  'nested_archives': nested, 'entries': records,
                  'opaque_non_nested_classes': sum(not r['directory'] and r['path'].endswith('.class')
                                                   for r in records),
                  'opaque_non_nested_files': sum(not r['directory'] and not r['path'].lower().endswith('.jar')
                                                 for r in records),
                  'all_regular_entry_crc_verified': True}
        self.archives[digest] = result
        self.stats['unique_archives'] += 1
        return result


def nested_labels(inventory, outer, digest, own, global_index, virtual=(), depth=0):
    if depth > MAX_DEPTH:
        raise ValueError('POST_NESTED_LABEL_DEPTH_BUDGET')
    known, unknown = [], []
    for child in inventory.archives[digest]['nested_archives']:
        chain = (*virtual, child['path'])
        base = {'outer_image_path': outer, 'virtual_path': outer + ':' + ':'.join(chain),
                'sha256': child['sha256'], 'bytes': child['bytes'],
                'entry_crc_verified': True, 'virtual_chain': list(chain),
                'inventory_sha256': child['inventory_sha256']}
        identity, reason = unique_identity(child['sha256'], own, global_index)
        if identity:
            known.append({**base, **identity})
        else:
            unknown.append({**base, 'status': 'UNKNOWN', 'reason': reason})
        if child['sha256'] in inventory.archives:
            more_known, more_unknown = nested_labels(inventory, outer, child['sha256'], own,
                                                    global_index, chain, depth + 1)
            known.extend(more_known)
            unknown.extend(more_unknown)
        else:
            unknown.append({**base, 'status': 'UNKNOWN_NESTED_CONTENT',
                            'reason': child['inspection_reason'],
                            'identity_label_separate': identity is not None})
    return known, unknown


def verified_pair(name):
    pair, work = ROOT / 'benchmarks/references' / name, ROOT / 'benchmarks/.work' / name
    receipt = read(pair / 'receipt.json')
    if receipt.get('artifact_tree_equal') is not True:
        raise ValueError('Controlled tree attestation absent')
    reference_hashes = {}
    for relative, expected in receipt['reference_hashes'].items():
        path = pair / relative
        if not path.resolve().is_relative_to(pair.resolve()) or sha(path) != expected:
            raise ValueError('Immutable reference binding failed')
        reference_hashes[path.relative_to(ROOT).as_posix()] = expected
    reference_hashes[(pair / 'receipt.json').relative_to(ROOT).as_posix()] = sha(pair / 'receipt.json')
    expected_tree = read(pair / 'application-tree.json')
    for filename in ('build-app.tar', 'runtime-app.tar'):
        actual, _ = exported_tree(work / filename)
        if actual != expected_tree:
            raise ValueError('Actual exported controlled tree changed')
    binding = archive_binding(work / 'image.tar', receipt['image_binding']['index_digest'])
    if binding != receipt['image_binding']:
        raise ValueError('Actual OCI chain changed')
    layers = Layers(work / 'image.tar')
    try:
        if layers.config_digest != binding['config_digest'] or len(layers.mapping) != 1:
            raise ValueError('Exact controlled scratch config/layer required')
        diff_id = next(iter(layers.mapping))
        stream, entries = layers.layer(diff_id)
        actual, _ = tree(entries, stream)
        if actual != expected_tree:
            raise ValueError('Actual image tree differs from controlled bytes')
    finally:
        layers.close()
    prior = read(PRIOR / (name + '.json'))
    if prior['actual_oci_binding'] != binding:
        raise ValueError('Prior standalone labels bind another image')
    return pair, work, receipt, expected_tree, prior, binding, diff_id, reference_hashes


def main():
    if OUTPUT.exists():
        raise FileExistsError('Completed/attempted namespace is immutable')
    OUTPUT.mkdir()
    shutil.copyfile(__file__, OUTPUT / 'executed-script.py')
    reports, input_manifest = [], {}
    for name in PAIRS:
        started = time.monotonic()
        pair, work, receipt, _expected_tree, prior, binding, diff_id, reference_hashes = verified_pair(name)
        modules = read(pair / 'module-labels.json')
        boms = {m['path']: read(pair / 'modules' / ('root' if m['path'] == '.' else m['path']) / 'sbom.json')
                for m in modules}
        global_index = identity_index([c for bom in boms.values() for c in all_components(bom)])
        inventory, output_modules = ArchiveInventory(), []
        with (work / 'runtime-app.tar').open('rb') as runtime_stream:
            archive, files, _ = index(runtime_stream, (work / 'runtime-app.tar').stat().st_size)
            with archive:
                for previous in prior['modules']:
                    module = next(m for m in modules if m['path'] == previous['path'])
                    own = identity_index(all_components(boms[module['path']]))
                    primaries, known_nested, unknown_nested, opaque = [], [], [], []
                    for entry in previous['unknown_standalone_files']:
                        path, digest = entry['image_path'], entry['sha256']
                        physical = files.get(path)
                        if physical is None or not physical.isfile() or physical.size > MAX_FILE:
                            raise ValueError('Primary candidate final regular physical bytes absent')
                        runtime_stream.seek(physical.offset_data)
                        # Every primary file is independently rehashed before content-cache reuse.
                        with tempfile.TemporaryFile() as spool:
                            with archive.extractfile(physical) as source:
                                actual = inventory.consume(source, physical.size, spool)
                            if actual != digest:
                                raise ValueError('Primary complete physical SHA256 changed')
                            spool.seek(0)
                            try:
                                content = inventory.inspect(spool, actual, physical.size)
                                inventory_reason = None
                            except (ValueError, zipfile.BadZipFile, NotImplementedError) as error:
                                content, inventory_reason = {}, rejection_reason(error)
                        effective = module.get('effective_output', {})
                        attested = (path == module['image_prefix'] + effective.get('file', '')
                                    and actual == effective.get('sha256'))
                        primary = {'image_path': path, 'sha256': actual, 'bytes': physical.size,
                                   'status': 'VERIFIED_EFFECTIVE_PRIMARY_SHA256' if attested else 'UNKNOWN_PRIMARY_CANDIDATE',
                                   'owner': previous['owner'] if attested else None,
                                   'inventory_sha256': content.get('inventory_sha256'),
                                   'entry_count': content.get('entry_count'),
                                   'nested_archive_count': len(content.get('nested_archives', [])),
                                   'all_regular_entry_crc_verified': bool(content),
                                   'inventory_reason': inventory_reason,
                                   'opaque_non_nested_classes': content.get('opaque_non_nested_classes')}
                        primaries.append(primary)
                        if content:
                            nested_known, nested_unknown = nested_labels(inventory, path, actual, own, global_index)
                            known_nested.extend(nested_known)
                            unknown_nested.extend(nested_unknown)
                        else:
                            unknown_nested.append({'outer_image_path': path, 'virtual_path': path,
                                'sha256': actual, 'status': 'UNKNOWN_PRIMARY_CONTENT',
                                'reason': inventory_reason})
                        if not content or content['opaque_non_nested_files']:
                            opaque.append({'image_path': path, 'sha256': actual,
                                           'status': 'UNKNOWN_SHADED_IDENTITY',
                                           'class_entries': content.get('opaque_non_nested_classes'),
                                           'non_nested_regular_entries': content.get('opaque_non_nested_files'),
                                           'reason': 'Complete entry hashes retained; entry names and primary owner do not prove absence/identity of shaded dependencies'})
                    delivered = (set(previous['known_standalone_coordinate_set']) |
                                 {row['coordinate'] for row in known_nested})
                    unresolved_primaries = [p for p in primaries if p['owner'] is None]
                    reasons = []
                    if unresolved_primaries:
                        reasons.append('PRIMARY_OUTPUT_IDENTITY_NOT_ATTESTED')
                    if unknown_nested:
                        reasons.append('NESTED_JAR_CONTROLLED_HASH_IDENTITY_UNKNOWN')
                    if opaque:
                        reasons.append('SHADED_NON_ARCHIVE_COMPONENT_SCOPE_NOT_ATTESTED')
                    output_modules.append({**previous,
                        'scope': 'Complete physical delivered standalone/nested JAR SHA256 identity labels; shaded identities remain separately UNKNOWN',
                        'primary_outputs': primaries, 'nested_file_labels': known_nested,
                        'unknown_nested_files': unknown_nested, 'unknown_shaded_content': opaque,
                        'known_delivered_coordinate_set': sorted(delivered),
                        'known_standalone_coordinate_set': previous['known_standalone_coordinate_set'],
                        'complete_delivered_archive_scope_attested': not unresolved_primaries and not unknown_nested,
                        'complete_image_component_scope_attested': not reasons,
                        'incomplete_scope_reasons': reasons,
                        'build_coordinates_without_confirmed_delivered_archive': sorted(
                            ({coord(c) for c in all_components(boms[module['path']]) if coord(c)} -
                             {previous['owner']}) - delivered)})
        inventory_path = OUTPUT / (name + '-archive-inventory.json')
        atomic_json(inventory_path, {'evaluation_only': True, 'archives_by_complete_sha256': inventory.archives})
        report = {'pair': name, 'commit': receipt['commit'], 'evaluation_only': True,
                  'actual_oci_binding': binding, 'actual_image_diff_id': diff_id,
                  'actual_build_runtime_image_trees_reverified': True,
                  'prediction_or_classifier_inputs_read': False,
                  'historical_scopes_scores_unchanged': True,
                  'archive_inventory_file': inventory_path.name, 'archive_inventory_sha256': sha(inventory_path),
                  'resources': inventory.stats, 'seconds': round(time.monotonic() - started, 3),
                  'modules': output_modules,
                  'known_standalone_files': sum(len(m['known_file_labels']) for m in output_modules),
                  'known_nested_files': sum(len(m['nested_file_labels']) for m in output_modules),
                  'unknown_nested_files': sum(len(m['unknown_nested_files']) for m in output_modules),
                  'attested_primary_outputs': sum(p['owner'] is not None for m in output_modules for p in m['primary_outputs']),
                  'unattested_primary_candidates': sum(p['owner'] is None for m in output_modules for p in m['primary_outputs']),
                  'delivered_archive_complete_owners': sum(m['complete_delivered_archive_scope_attested'] for m in output_modules),
                  'full_component_complete_owners': sum(m['complete_image_component_scope_attested'] for m in output_modules)}
        atomic_json(OUTPUT / (name + '.json'), report)
        reports.append(report)
        input_manifest[name] = {'reference_hashes': reference_hashes,
            'previous_standalone_label_sha256': sha(PRIOR / (name + '.json')),
            'physical_archives': {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in
                                 (work / 'build-app.tar', work / 'runtime-app.tar', work / 'image.tar')}}
        print(name, report['known_standalone_files'], report['known_nested_files'],
              report['unknown_nested_files'], report['delivered_archive_complete_owners'], flush=True)
    atomic_json(OUTPUT / 'input-manifest.json', {'evaluation_only': True, 'post_only': True,
        'prediction_or_classifier_inputs_read': False,
        'script_sha256': sha(Path(__file__)), 'inputs': input_manifest,
        'output_reports': {name + '.json': sha(OUTPUT / (name + '.json')) for name in PAIRS},
        'dependency_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in
            (ROOT / 'benchmarks/bounded_jar_evidence.py', ROOT / 'benchmarks/compare_java_js.py',
             ROOT / 'benchmarks/audit_reactor_scope_r107.py', ROOT / 'benchmarks/label_reactor_packaged_scope_r108.py',
             ROOT / 'benchmarks/paired_express.py', ROOT / 'benchmarks/seekable_layer_index.py')},
        'post_only_resource_policy': {'full_member_reads': MAX_READ, 'outer_jar': MAX_FILE,
            'nested_jar': MAX_NESTED, 'aggregate_directory': MAX_DIRECTORY,
            'aggregate_entries': MAX_ENTRIES, 'single_directory': 2 * CHUNK,
            'inflate_ratio': MAX_RATIO, 'depth': MAX_DEPTH,
            'runtime_budgets_or_rules_changed': False}})
    atomic_json(OUTPUT / 'report.json', {'evaluation_only': True, 'post_only': True,
        'prediction_or_classifier_inputs_read': False, 'historical_scopes_scores_unchanged': True,
        'new_scans_builds_classifier_input_changes': False,
        'reports': reports,
        'limits': ['Primary effective-output hash binding is separate from dependency identity',
                   'Opaque primary classes/resources do not establish or exclude shaded component identities',
                   'Nested packaging extras without a unique controlled CDX SHA256 stay UNKNOWN',
                   'No classifier output was used to choose expected names or scope']})


if __name__ == '__main__':
    main()

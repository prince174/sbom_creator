"""Inspect prior unconfirmed JARs from actual image bytes, without an oracle.

Cached Syft/Trivy and prior payload facts select candidates only. Current
production reader guards bind the image config, final path, layer and nested
chain. This benchmark changes neither the runtime classifier nor its facts.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from sbom_creator.image_java import bounded_jar_evidence as guards
from sbom_creator.image_java.directory_jar_evidence import JarFiles
from sbom_creator.image_java.stored_jar_evidence import CachedWindow
from sbom_creator.image_java.trivy_payload_bridge import (
    artifact_key,
    canonical_path,
    properties,
)

ROOT = Path(__file__).resolve().parents[1]
MAX_CAPTURE = 32*1024
MAX_SHA_READ = 32*1024**2
CASES = {
    'microservices': {
        'archive': 'benchmarks/.work/paired-petclinic-microservices-r104/image.tar',
        'prediction': 'benchmarks/results/mvp-r107-container-v1/microservices/workspace/analysis'},
    'dropwizard': {
        'archive': 'benchmarks/.work/paired-dropwizard-reactor-v1/image.tar',
        'prediction': 'benchmarks/results/mvp-r107-v1/java/dropwizard/analysis'},
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')


def declarations(raw):
    """Literal metadata only; this is neither Maven resolution nor authority."""
    text = raw.decode('iso-8859-1')
    result = defaultdict(list)
    unsupported = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(('#', '!')):
            continue
        match = re.fullmatch(r'\s*(groupId|artifactId|version)\s*[=:]\s*([^\s\\]+)\s*', line)
        if match:
            result[match[1]].append(match[2])
        elif '\\' in line:
            unsupported = True
    return {'literal_values': dict(result), 'unsupported_escape_syntax': unsupported,
            'authority': 'unverified archive metadata'}


def manifest(raw):
    text = raw.decode('utf-8')
    unfolded = []
    for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        if not line:
            break  # Only the main section is interpreted.
        if line.startswith(' ') and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    fields = defaultdict(list)
    for line in unfolded:
        key, separator, value = line.partition(': ')
        if separator:
            fields[key].append(value)
    return dict(fields)


def open_chain(reader, artifact, final_files):
    binding = artifact_key(artifact, final_files)
    location = artifact['locations'][0]
    outer = canonical_path(location['path'])
    virtual = artifact.get('metadata', {}).get('virtualPath', outer)
    chain = virtual[len(outer)+1:].split(':') if virtual != outer else []
    if len(chain) > guards.MAX_DEPTH:
        raise guards.BudgetExceeded('Nested archive depth')
    key = (outer,)
    stream = reader.source(outer)
    for name in chain:
        archive = reader.archive(key, stream)
        member = archive.getinfo(canonical_path(name).lstrip('/'))
        if (member.file_size > guards.MAX_NESTED
                or member.file_size > max(1, member.compress_size)*guards.MAX_RATIO):
            raise guards.BudgetExceeded('Nested archive inflate budget')
        key += (member.filename,)
        if key not in reader.spools:
            reader.nested(key, archive, member, stream)
        stream = reader.spools[key]
    return binding, key, stream, reader.archive(key, stream)


def full_digests(reader, stream, global_reads):
    """Complete digest pass; charge both original 8GiB and extra 32MiB ledgers."""
    window = stream.window if isinstance(stream, CachedWindow) else None
    if window is not None:
        raw, offset, size = window.stream, window.offset, window.size
    else:
        raw = stream
        raw.seek(0, 2)
        offset, size = 0, raw.tell()
    if size > MAX_SHA_READ-global_reads[0]:
        return {'status': 'UNKNOWN', 'reason': 'inspection_full_digest_32MiB_budget', 'bytes': size}
    if size > 8*1024**3-reader.stats['verification_read_bytes']:
        return {'status': 'UNKNOWN', 'reason': 'reader_full_verification_8GiB_budget', 'bytes': size}
    original = raw.tell()
    sha256, sha1, crc, remaining = hashlib.sha256(), hashlib.sha1(usedforsecurity=False), 0, size
    raw.seek(offset)
    try:
        while remaining:
            if time.monotonic()-reader.started > 180:
                raise guards.BudgetExceeded('Witness job deadline')
            block = raw.read(min(1024*1024, remaining))
            if not block:
                raise ValueError('Truncated inspection digest stream')
            sha256.update(block)
            sha1.update(block)
            crc = zlib.crc32(block, crc)
            reader.stats['verification_read_bytes'] += len(block)
            global_reads[0] += len(block)
            remaining -= len(block)
    finally:
        raw.seek(original)
    cached = reader.verified_stored.get((id(raw), offset, size)) if window else None
    if cached and cached != (sha256.hexdigest(), crc):
        raise ValueError('Inspection digests differ from prior full stored-member verification')
    return {'status': 'complete', 'bytes': size, 'sha256': sha256.hexdigest(),
        'sha1': sha1.hexdigest(), 'crc32': f'{crc:08x}',
        'parent_stored_crc_and_sha256_rechecked': bool(cached),
        'whole_archive_crc_note': 'No declared whole-JAR CRC exists for flat files; computed CRC is not publisher authentication',
        'physical_range': {'offset': offset, 'bytes': size},
        'method': 'fresh complete read of exact bound JAR range'}


def capture(archive):
    remaining, records = MAX_CAPTURE, []
    items = archive.infolist()
    metadata = [m for m in items if m.filename == 'META-INF/MANIFEST.MF'
                or re.fullmatch(r'META-INF/maven/[^/]+/[^/]+/pom\.properties', m.filename)]
    metadata.sort(key=lambda m: (m.filename != 'META-INF/MANIFEST.MF', m.filename))
    for item in metadata:
        name_cost = len(item.filename.encode('utf-8'))
        if name_cost > remaining:
            break
        if (name_cost+item.file_size > remaining
                or item.file_size > max(1, item.compress_size)*guards.MAX_RATIO):
            remaining -= name_cost
            records.append({'name': item.filename, 'status': 'UNKNOWN', 'reason': 'capture_byte_or_ratio_budget'})
            continue
        with archive.open(item) as stream:
            raw = stream.read(item.file_size+1)
        if len(raw) != item.file_size:
            raise ValueError('Metadata file length mismatch')
        remaining -= name_cost+len(raw)
        record = {'name': item.filename, 'bytes': len(raw), 'crc_verified_by_zipfile': True}
        try:
            record['text'] = raw.decode('utf-8')
        except UnicodeDecodeError:
            record['base64'] = base64.b64encode(raw).decode()
        if item.filename == 'META-INF/MANIFEST.MF':
            try:
                record['main_fields'] = manifest(raw)
            except UnicodeDecodeError:
                record['main_fields'] = 'UNKNOWN: non-UTF8 manifest'
        else:
            record['properties'] = declarations(raw)
        records.append(record)
    names = []
    for item in items:
        cost = len(item.filename.encode('utf-8'))
        if cost > remaining:
            break
        remaining -= cost
        names.append(item.filename)
    return {'entry_count': len(items), 'entry_names': names,
        'entry_names_truncated': len(names) != len(items),
        'captured_raw_name_and_metadata_bytes': MAX_CAPTURE-remaining,
        'metadata': records, 'class_entry_count': sum(m.filename.endswith('.class') for m in items)}


def inspect_case(name, output, global_reads):
    case = CASES[name]
    source = ROOT/case['prediction']
    image = json.loads((source/'image-original.syft.json').read_text())
    peer = json.loads((source/'image-peer.cdx.json').read_text())
    prior = json.loads((source/'provenance.json').read_text())['image']['payload_evidence']
    config = image['source']['metadata']['imageID']
    assert properties(peer['metadata']['component'], 'ImageID') == [config]
    by_path = defaultdict(list)
    for entry in image['files']:
        try:
            by_path[canonical_path(entry['location']['path'])].append(entry)
        except ValueError:
            continue
    peer_by_path = defaultdict(list)
    for component in peer.get('components', []):
        paths, layers = properties(component, 'FilePath'), properties(component, 'LayerDiffID')
        if len(paths) == len(layers) == 1:
            try:
                peer_by_path[(canonical_path(paths[0]), layers[0])].append(component.get('purl'))
            except ValueError:
                continue
    candidates = [a for a in image['artifacts'] if a.get('foundBy') == 'java-archive-cataloger'
                  and prior.get(a['id'], {}).get('status') != 'confirmed']
    assert len(candidates) <= 4096
    rows, started = [], time.monotonic()
    with tempfile.TemporaryDirectory(prefix='metadata-inspection-', dir=ROOT/'benchmarks/.work') as temporary:
        reader = JarFiles(ROOT/case['archive'], image, temporary=temporary)
        try:
            for artifact in candidates:
                row = {'artifact_id': artifact['id'], 'observed_identity': {
                    key: artifact.get(key) for key in ('purl', 'name', 'version')},
                    'prior_payload_fact': copy.deepcopy(prior.get(artifact['id'])),
                    'classification_changed': False}
                try:
                    binding, _, stream, archive = open_chain(reader, artifact, by_path)
                    row['binding'] = {'path': binding[0], 'layer': binding[1], 'config': config}
                    row['peer_observed_purls'] = peer_by_path.get(binding, [])
                    row['inspection'] = capture(archive)
                    if row['inspection']['class_entry_count'] == 0:
                        row['whole_jar_digests'] = full_digests(reader, stream, global_reads)
                    row['status'] = 'inspected'
                    if row['inspection']['class_entry_count'] == 0 and sum(
                            r.get('inspection', {}).get('class_entry_count') == 0 for r in rows) < 5:
                        print(json.dumps({'case': name, 'classless_archive': row}, ensure_ascii=True), flush=True)
                except (ValueError, OSError, KeyError, RuntimeError) as error:
                    row['status'] = 'UNKNOWN'
                    row['error_type'] = type(error).__name__
                    row['reason'] = str(error)[:256]
                finally:
                    for archive in reader.zips.values():
                        archive.close()
                    reader.zips.clear()
                rows.append(row)
                with (output/f'{name}.jsonl').open('a', encoding='utf-8') as log:
                    log.write(json.dumps(row)+'\n')
            report = {'case': name, 'cached_producer_outputs': True, 'fresh_physical_reads': True,
                'reference_accessed': False, 'classifier_changed': False,
                'elapsed_seconds': round(time.monotonic()-started, 3),
                'candidate_selection': 'all prior unconfirmed original Syft Java observations; no expected package names',
                'candidates': len(candidates), 'status_counts': dict(Counter(r['status'] for r in rows)),
                'classless_observations': sum(r.get('inspection', {}).get('class_entry_count') == 0 for r in rows),
                'extra_complete_digest_read_bytes_shared': global_reads[0],
                'jar_resources': reader.stats, 'layer_resources': reader.layers_reader.stats, 'observations': rows}
            write(output/f'{name}.json', report)
            return report
        finally:
            reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=ROOT/'benchmarks/results/archive-metadata-inspection-r108-v1')
    parser.add_argument('--cases', nargs='+', choices=CASES, default=['microservices', 'dropwizard'])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    inputs = {}
    for name in args.cases:
        case = CASES[name]
        paths = [ROOT/case['archive'], *(ROOT/case['prediction']/p for p in
            ('image-original.syft.json', 'image-peer.cdx.json', 'provenance.json'))]
        inputs[name] = {p.relative_to(ROOT).as_posix(): sha(p) for p in paths}
    code = {p.relative_to(ROOT).as_posix(): sha(p) for p in (ROOT/'src').rglob('*')
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    write(args.output/'freeze.json', {'frozen_at': datetime.now(UTC).isoformat(),
        'script_sha256': sha(Path(__file__)), 'code_hashes': code, 'input_hashes': inputs,
        'reference_accessed': False, 'max_capture_raw_bytes_per_archive': MAX_CAPTURE,
        'extra_digest_read_bytes_all_cases': MAX_SHA_READ,
        'reader_budgets': 'unchanged; including 8GiB verification ledger and 180s deadline per image'})
    global_reads, summary = [0], {}
    for name in args.cases:
        report = inspect_case(name, args.output, global_reads)
        summary[name] = {k: v for k, v in report.items() if k not in ('observations',)}
        print(json.dumps({'completed': name, 'summary': summary[name]}), flush=True)
    write(args.output/'summary.json', summary)


if __name__ == '__main__':
    main()

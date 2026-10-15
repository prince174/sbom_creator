"""Evaluation-only boot packaging labels from controlled Maven artifact bytes.

Never imported by the service or classifier. Build declarations are not silently
replaced with the packaged subset; both sets and unresolved labels are retained.
"""
import hashlib
import json
import tarfile
import zipfile
from collections import defaultdict
from pathlib import PurePosixPath

from compare_java_js import all_components, coord
from paired_express import export_from_image
from run import ROOT, atomic_json

MAX_JAR = 128 * 1024 * 1024


def native_coordinates(tree):
    result = defaultdict(set)
    pending = list(tree.get('children', []))
    while pending:
        node = pending.pop()
        pending.extend(node.get('children', []))
        if node.get('type') != 'jar':
            continue
        gav = (node['groupId'], node['artifactId'], node['version'])
        classifier = '-' + node['classifier'] if node.get('classifier') else ''
        filename = node['artifactId'] + '-' + node['version'] + classifier + '.jar'
        result[filename].add(gav)
    return result


def payload_kind(stream):
    with zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        if len(members) > 100_000:
            raise ValueError('ZIP index budget exceeded')
        names = [m.filename for m in members if not m.is_dir()]
        classes = [m for m in members if m.filename.endswith('.class') and m.file_size >= 4]
        for member in classes:
            with archive.open(member) as content:
                if content.read(4) == b'\xca\xfe\xba\xbe':
                    return 'class_payload'
        resources = [n for n in names if (not n.startswith('META-INF/') or n.startswith('META-INF/resources/')) and not n.endswith('.class') and
                     PurePosixPath(n).name.upper() not in ('LICENSE', 'LICENSE.TXT', 'NOTICE', 'NOTICE.TXT')]
        return 'resource_payload' if resources else 'metadata_only'


def main():
    reference_dir = ROOT / 'benchmarks/references/paired-spring-petclinic-v1'
    work = ROOT / 'benchmarks/.work/paired-spring-petclinic-v1'
    output = ROOT / 'benchmarks/results/boot-packaging-labels-v2'
    if (output / 'report.json').exists():
        raise FileExistsError('Completed labels are immutable')
    receipt = json.loads((reference_dir / 'receipt.json').read_bytes())
    for name, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((reference_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Original reference bytes changed')
    native = json.loads((reference_dir / 'dependency-tree.json').read_bytes())
    candidates = native_coordinates(native)
    copied = work / 'resolved-dependency-jars.tar'
    if not copied.exists():
        export_from_image((work / 'build.id').read_text().strip(), [('/src/target/dependency', copied, True)], 'resolved-deps')
    resolved, unresolved = {}, []
    with tarfile.open(copied) as archive:
        for member in archive:
            if not member.isfile() or not member.name.endswith('.jar'):
                continue
            if member.size > MAX_JAR:
                raise ValueError('Controlled JAR budget exceeded')
            filename = PurePosixPath(member.name).name
            choices = candidates.get(filename, set())
            if len(choices) != 1:
                unresolved.append({'filename': filename, 'reason': 'native_coordinate_not_unique'})
                continue
            gav = next(iter(choices))
            with archive.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            with archive.extractfile(member) as stream:
                kind = payload_kind(stream)
            purl = 'pkg:maven/' + gav[0] + '/' + gav[1] + '@' + gav[2]
            resolved[purl] = {'sha256': digest, 'filename': filename, 'payload_kind': kind}
    by_hash = defaultdict(list)
    for purl, value in resolved.items():
        by_hash[value['sha256']].append(purl)
    packaged, unknown_packaged = {}, []
    with tarfile.open(work / 'runtime-app.tar') as archive:
        roots = [m for m in archive if m.isfile() and m.name.endswith('.jar')]
        if len(roots) != 1 or roots[0].size > MAX_JAR:
            raise ValueError('Boot outer JAR not unique/bounded')
        with archive.extractfile(roots[0]) as stream, zipfile.ZipFile(stream) as boot:
            members = boot.infolist()
            if len(members) > 100_000:
                raise ValueError('Boot index budget exceeded')
            for member in members:
                if not member.filename.startswith('BOOT-INF/lib/') or not member.filename.endswith('.jar'):
                    continue
                if member.file_size > MAX_JAR:
                    raise ValueError('Nested JAR budget exceeded')
                with boot.open(member) as jar:
                    digest = hashlib.file_digest(jar, 'sha256').hexdigest()
                matches = by_hash.get(digest, [])
                if len(matches) == 1:
                    packaged[matches[0]] = {'path': member.filename, **resolved[matches[0]]}
                else:
                    unknown_packaged.append({'path': member.filename, 'sha256': digest, 'reason': 'no_unique_controlled_resolved_hash_match'})
    bom = json.loads((reference_dir / 'sbom.json').read_bytes())
    owner = coord(bom['metadata']['component'])
    expected = {coord(c) for c in all_components(bom) if coord(c)} - {owner}
    if set(resolved) - expected:
        raise ValueError('Native copied dependency not in build oracle')
    absent = {p: v for p, v in resolved.items() if p not in packaged}
    root_declared = {'pkg:maven/' + c['groupId'] + '/' + c['artifactId'] + '@' + c['version']
                     for c in native.get('children', [])}
    report = {'project': receipt['project'], 'commit': receipt['commit'], 'evaluation_only': True,
              'supersedes_payload_taxonomy': 'v1 incorrectly treated META-INF/resources assets as metadata-only; coordinate/hash labels unchanged',
              'runtime_changed': False, 'build_reference_components': len(expected),
              'resolved_artifact_labels': len(resolved), 'packaged_labels': len(packaged),
              'packaged_payload_counts': {k: sum(v['payload_kind'] == k for v in packaged.values())
                                         for k in ('class_payload', 'resource_payload', 'metadata_only')},
              'root_direct_build': sorted(root_declared),
              'root_direct_packaged': sorted(root_declared & packaged.keys()),
              'root_direct_not_packaged': sorted(root_declared - packaged.keys()),
              'packaged': packaged, 'resolved_not_packaged': absent,
              'unlabelled_build_reference': sorted(expected - resolved.keys()),
              'unknown_packaged': unknown_packaged, 'unresolved_native_files': unresolved,
              'proof': 'Controlled Maven copy-dependencies + unique native filename coordinate + exact SHA256 match to actual nested JAR; no alias guessing',
              'scope_boundary': 'Full declared build direct graph remains separate. Absent build artifacts are not automatically runtime FN. This label file must never become an analyzer input.'}
    atomic_json(output / 'report.json', report)
    print(json.dumps({k: v for k, v in report.items() if k not in ('packaged', 'resolved_not_packaged')}))


if __name__ == '__main__':
    main()

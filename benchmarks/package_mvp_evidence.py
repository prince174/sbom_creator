"""Losslessly package R105 JSON evidence without modifying its original bytes.

Large JSON copies use content-addressed deterministic gzip; small artifacts stay
readable. Exact-path gitignore entries hide only successfully packaged originals.
Run `pack`, `verify`, or `restore`; the default dry-run never writes anything.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT/'benchmarks/results'
NAMES = ('mvp-image-r105-v1', 'mvp-image-r105-v2', 'mvp-image-r105-serial-boot',
         'mvp-js-r105-v1', 'mvp-container-r105-v1')
MANIFEST = RESULTS/'mvp-r105-evidence-manifest.json'
PACKED = RESULTS/'mvp-r105-packed'
THRESHOLD = 256*1024
CHUNK = 1024*1024
BEGIN = '# BEGIN R105 exact packed-evidence originals (package_mvp_evidence.py)'
END = '# END R105 exact packed-evidence originals'
SKIP = {'workspace', '.work', '__pycache__', '.git'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(path):
    return path.relative_to(ROOT).as_posix()


def safe_path(value):
    path = ROOT.joinpath(value).resolve()
    if not path.is_relative_to(RESULTS.resolve()):
        raise ValueError('Evidence path escaped results directory')
    return path


def read_manifest():
    if not MANIFEST.is_file():
        return None
    document = json.loads(MANIFEST.read_text('utf-8'))
    if document.get('format_version') != 1 or tuple(document.get('namespaces', ())) != NAMES:
        raise ValueError('Unexpected evidence manifest contract')
    return document


def candidates(previous):
    paths = []
    for name in NAMES:
        namespace = RESULTS/name
        if not namespace.is_dir():
            raise ValueError('Expected evidence namespace is missing: '+name)
        for parent, directories, files in os.walk(namespace, followlinks=False):
            directories[:] = sorted(d for d in directories if d not in SKIP and not (Path(parent)/d).is_symlink())
            paths.extend(Path(parent)/f for f in sorted(files)
                         if f.endswith('.json') and not (Path(parent)/f).is_symlink())
    # Respect other gitignore rules, including container scratch workspaces.
    request = b''.join(relative(path).encode()+b'\0' for path in paths)
    result = subprocess.run(['git', 'check-ignore', '--no-index', '--stdin', '-z'],
                            input=request, capture_output=True, cwd=ROOT, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError('Cannot establish ignored evidence paths')
    ignored = {p.decode() for p in result.stdout.split(b'\0') if p}
    owned = set((previous or {}).get('artifacts', {}))
    return [p for p in paths if relative(p) not in ignored or relative(p) in owned]


def gzip_copy(source, destination):
    """Streaming, filename-free gzip with zero timestamp; never rewrite raw input."""
    with (source.open('rb') as incoming, destination.open('xb') as outgoing,
          gzip.GzipFile(filename='', mode='wb', fileobj=outgoing, mtime=0, compresslevel=9) as compressed):
        while block := incoming.read(CHUNK):
            compressed.write(block)


def verify_record(name, record):
    raw = safe_path(name)
    stored = safe_path(record['path']) if record['storage'] == 'gzip' else raw
    if not stored.is_file() or stored.stat().st_size != record.get('stored_bytes', record['bytes']):
        raise ValueError('Missing or differently sized evidence: '+relative(stored))
    if record['storage'] == 'gzip':
        if sha(stored) != record['stored_sha256']:
            raise ValueError('Compressed evidence checksum mismatch: '+name)
        digest, total = hashlib.sha256(), 0
        with gzip.open(stored, 'rb') as stream:
            while block := stream.read(CHUNK):
                total += len(block)
                if total > record['bytes']:
                    raise ValueError('Expanded evidence exceeds manifest size: '+name)
                digest.update(block)
        if total != record['bytes'] or digest.hexdigest() != record['sha256']:
            raise ValueError('Expanded evidence checksum mismatch: '+name)
    if raw.is_file() and (raw.stat().st_size != record['bytes'] or sha(raw) != record['sha256']):
        raise ValueError('Original evidence changed after snapshot: '+name)
    return raw, stored


def ignore_originals(artifacts):
    path = ROOT/'.gitignore'
    contents = path.read_text('utf-8')
    if BEGIN in contents:
        before, remainder = contents.split(BEGIN, 1)
        _, after = remainder.split(END, 1)
        contents = before.rstrip()+after
    rules = ['/'+name for name, record in sorted(artifacts.items()) if record['storage'] == 'gzip']
    block = '\n'.join([BEGIN, *rules, END])
    path.write_text(contents.rstrip()+'\n\n'+block+'\n', encoding='utf-8', newline='\n')


def pack():
    previous = read_manifest()
    artifacts = dict((previous or {}).get('artifacts', {}))
    for name, record in artifacts.items():
        verify_record(name, record)
    PACKED.mkdir(parents=True, exist_ok=True)
    for path in candidates(previous):
        name, size, digest = relative(path), path.stat().st_size, sha(path)
        if name in artifacts:
            continue
        record = {'storage': 'raw', 'bytes': size, 'sha256': digest}
        if size > THRESHOLD:
            destination = PACKED/(digest+'.json.gz')
            if not destination.is_file():
                with tempfile.TemporaryDirectory(prefix='pack-', dir=PACKED) as work:
                    pending = Path(work)/'evidence.gz'
                    gzip_copy(path, pending)
                    if path.stat().st_size != size or sha(path) != digest:
                        raise ValueError('Evidence changed while compressing: '+name)
                    pending.replace(destination)
            record.update(storage='gzip', path=relative(destination), stored_bytes=destination.stat().st_size,
                          stored_sha256=sha(destination))
        artifacts[name] = record
        verify_record(name, record)
    document = {'format_version': 1, 'namespaces': list(NAMES), 'threshold_bytes': THRESHOLD,
                'compression': 'gzip level9 filename-empty mtime0; raw bytes unchanged',
                'identity': 'sha256 of exact original bytes; JSON is never reserialized',
                'artifacts': dict(sorted(artifacts.items()))}
    MANIFEST.write_text(json.dumps(document, ensure_ascii=True, indent=2)+'\n', encoding='utf-8', newline='\n')
    ignore_originals(artifacts)
    return document


def verify(document, restore=False):
    for name, record in document['artifacts'].items():
        raw, stored = verify_record(name, record)
        if restore and record['storage'] == 'gzip' and not raw.exists():
            raw.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(stored, 'rb') as incoming, raw.open('xb') as outgoing:
                while block := incoming.read(CHUNK):
                    outgoing.write(block)
            verify_record(name, record)
    return document


def summary(document):
    artifacts = document['artifacts']
    packed = {r['path']: r for r in artifacts.values() if r['storage'] == 'gzip'}
    return {'files': len(artifacts), 'large_json_files': sum(r['storage'] == 'gzip' for r in artifacts.values()),
            'unique_gzip_files': len(packed), 'original_bytes': sum(r['bytes'] for r in artifacts.values()),
            'tracked_json_and_gzip_bytes': sum(r['stored_bytes'] for r in packed.values())+
                sum(r['bytes'] for r in artifacts.values() if r['storage'] == 'raw'),
            'manifest': relative(MANIFEST), 'originals_modified_or_deleted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=('dry-run', 'pack', 'verify', 'restore'), default='dry-run')
    args = parser.parse_args()
    if args.mode == 'pack':
        document = pack()
    elif args.mode in ('verify', 'restore'):
        document = read_manifest()
        if document is None:
            raise ValueError('No evidence manifest to verify')
        verify(document, restore=args.mode == 'restore')
    else:
        previous = read_manifest()
        paths = candidates(previous)
        print(json.dumps({'mode': 'dry-run', 'json_files': len(paths),
            'original_bytes': sum(p.stat().st_size for p in paths),
            'large_json_files': sum(p.stat().st_size > THRESHOLD for p in paths)}, indent=2))
        return
    print(json.dumps(summary(document), indent=2))


if __name__ == '__main__':
    main()

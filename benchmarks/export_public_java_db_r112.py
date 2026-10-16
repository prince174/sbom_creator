"""Copy the retained R111 public DB into a new R112 cache; no network or oracle."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r112-db-export-v1'
DESTINATION = ROOT / 'benchmarks/.work/java-db-r112'
IMAGE = 'sha256:4b31c639de2cb444b115dd5ced5bf1fbc9ce98cf3657b6fd2f0923a867f13698'
VOLUME = 'sbom-r111-public-java-1792134539387152100'
EXPECTED = {
    'trivy-java.db': '491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59',
    'metadata.json': '40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2'}
PROGRAM = r'''
import hashlib,json,os,stat
from pathlib import Path
source=Path('/retained/trivy-cache/java-db')
target=Path('/export/cache')
expected=json.loads(os.environ['R112_EXPECTED'])
assert set(p.name for p in source.iterdir()) == set(expected)
assert not target.exists()
stage=Path('/export/cache-export-stage')
stage.mkdir()
(stage/'java-db').mkdir()
facts={}
for name,digest in expected.items():
    src=source/name
    info=src.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 2*1024**3
    copied=0
    h=hashlib.sha256()
    with src.open('rb') as stream,(stage/'java-db'/name).open('xb') as out:
        while block:=stream.read(1024**2):
            copied+=len(block)
            assert copied <= 2*1024**3
            h.update(block)
            out.write(block)
    assert copied == info.st_size and h.hexdigest() == digest
    facts[name]={'bytes':copied,'sha256':h.hexdigest()}
stage.rename(target)
print(json.dumps({'status':'passed','network':False,'source_volume_read_only':True,
    'reference_or_old_database_accessed':False,'files':facts}))
'''


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def main():
    if OUTPUT.exists() or DESTINATION.exists():
        raise FileExistsError('Never overwrite an attempted DB export')
    OUTPUT.mkdir()
    DESTINATION.mkdir(parents=True)
    (OUTPUT/'executed-script.py').write_bytes(Path(__file__).read_bytes())
    (OUTPUT/'container-program.py').write_bytes(PROGRAM.encode())
    write(OUTPUT/'freeze.json', {'script_sha256': sha(__file__),
        'program_sha256': hashlib.sha256(PROGRAM.encode()).hexdigest(),
        'image': IMAGE, 'volume': VOLUME, 'expected_files': EXPECTED,
        'source_mount_read_only': True, 'network': 'none', 'oracle_read': False,
        'old_database_read_or_written': False})
    command=['docker','run','--rm','--pull=never','--network=none','--read-only',
        '--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--memory=256m','--cpus=1','--pids-limit=64',
        '--mount',f'type=volume,src={VOLUME},dst=/retained,readonly',
        '--mount',f'type=bind,src={DESTINATION},dst=/export',
        '--env','R112_EXPECTED='+json.dumps(EXPECTED),
        '--entrypoint=python',IMAGE,'-c',PROGRAM]
    env={key: value for key,value in os.environ.items() if key.upper() in {
        'SYSTEMROOT','WINDIR','SYSTEMDRIVE','PATH','PATHEXT','TEMP','TMP',
        'PROGRAMFILES','PROGRAMDATA','APPDATA','LOCALAPPDATA','ALLUSERSPROFILE'}}
    started=time.monotonic()
    result=subprocess.run(command, env=env, capture_output=True, text=True, timeout=300, check=False)
    (OUTPUT/'container.stdout').write_text(result.stdout, encoding='utf-8')
    (OUTPUT/'container.stderr').write_text(result.stderr, encoding='utf-8')
    write(OUTPUT/'run.json', {'exit_code':result.returncode,'seconds':time.monotonic()-started,
        'command':command,'program_sha256':hashlib.sha256(PROGRAM.encode()).hexdigest()})
    result.check_returncode()
    facts=json.loads(result.stdout)
    for name,digest in EXPECTED.items():
        assert sha(DESTINATION/'cache/java-db'/name) == digest
    write(OUTPUT/'report.json', {**facts,'host_hashes_verified':True,
        'destination':DESTINATION.relative_to(ROOT).as_posix()})
    print(json.dumps({'status':'passed','destination':str(DESTINATION/'cache')}))


if __name__ == '__main__':
    main()

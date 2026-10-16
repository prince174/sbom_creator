"""Native Linux peer-path negative; tiny fixture, no DB, scanner, network or oracle."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r112-native-path-v2'
IMAGE = 'sha256:4b31c639de2cb444b115dd5ced5bf1fbc9ce98cf3657b6fd2f0923a867f13698'
PROGRAM = r'''
import hashlib,json,sys,tempfile
from pathlib import Path
sys.path.insert(0,'/candidate')
from sbom_creator.acquire import Settings
from sbom_creator.image_java import runtime
from sbom_creator.image_java.java_database_cache import DatabaseCacheError
assert str(Path(runtime.__file__)).startswith('/candidate/')
observed={p.relative_to('/candidate').as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
    for p in sorted(Path('/candidate').rglob('*')) if p.is_file()}
calls=[]
def forbidden(*args,**kwargs):
    calls.append(args)
    raise AssertionError('unsafe path invoked Trivy/downloader')
runtime.run_command=forbidden
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    outside=root/'outside'
    outside.mkdir()
    link=root/'linked-parent'
    link.symlink_to(outside,target_is_directory=True)
    temporary=root/'job'
    temporary.mkdir()
    try:
        runtime.peer(root/'unused.tar',Settings(trivy_cache_dir=str(link/'new-child/cache')),temporary)
    except DatabaseCacheError as error:
        assert error.code == 'CACHE_INVALID'
    else:
        raise AssertionError('linked ancestor accepted')
    assert not (outside/'new-child').exists() and not calls
print(json.dumps({'status':'passed','native_symlink_peer_guard':True,'scanner_or_downloader_calls':0,
    'outside_child_created':False,'network':'none','public_database_read':False,
    'oracle_read':False,'skips':0,'installed_source_sha256':observed}))
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve every native integration attempt')
    snapshot=OUTPUT/'executed-source'
    shutil.copytree(ROOT/'src/sbom_creator',snapshot/'sbom_creator',
        ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    (OUTPUT/'executed-script.py').write_bytes(Path(__file__).read_bytes())
    (OUTPUT/'program.py').write_bytes(PROGRAM.encode())
    sources={p.relative_to(snapshot).as_posix():sha(p) for p in sorted(snapshot.rglob('*')) if p.is_file()}
    freeze={'source_sha256':sources,'program_sha256':hashlib.sha256(PROGRAM.encode()).hexdigest(),
        'script_sha256':sha(__file__),'image':IMAGE,'network':'none','oracle_read':False}
    (OUTPUT/'freeze.json').write_text(json.dumps(freeze,indent=2)+'\n',encoding='utf-8')
    command=['docker','run','--rm','--pull=never','--network=none','--read-only',
        '--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--memory=256m','--cpus=1','--pids-limit=64','--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777',
        '--mount',f'type=bind,src={snapshot},dst=/candidate,readonly',
        '--env','TMPDIR=/tmp','--entrypoint=python',IMAGE,'-B','-c',PROGRAM]
    env={k:v for k,v in os.environ.items() if k.upper() in {
        'SYSTEMROOT','WINDIR','SYSTEMDRIVE','PATH','PATHEXT','TEMP','TMP',
        'PROGRAMFILES','PROGRAMDATA','APPDATA','LOCALAPPDATA','ALLUSERSPROFILE'}}
    result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=60,check=False)
    (OUTPUT/'stdout.log').write_text(result.stdout,encoding='utf-8')
    (OUTPUT/'stderr.log').write_text(result.stderr,encoding='utf-8')
    (OUTPUT/'run.json').write_text(json.dumps({'command':command,'exit_code':result.returncode},indent=2)+'\n',encoding='utf-8')
    result.check_returncode()
    report=json.loads(result.stdout)
    assert report['installed_source_sha256'] == sources and len(sources) == 48
    assert all(sha(ROOT/'src'/name) == digest for name,digest in sources.items())
    (OUTPUT/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('PASS native peer symlink guard; 48 source hashes; no tool/download/network')


if __name__ == '__main__':
    main()

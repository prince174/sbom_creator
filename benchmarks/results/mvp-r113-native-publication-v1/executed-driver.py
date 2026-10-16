"""Native atomic publication/cleanup contracts; toy files, no scans or oracle."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT/'benchmarks/results/mvp-r113-native-publication-v1'
IMAGE = 'sha256:46911efe835d118cae7f5decde254c988f6d32504482405bf8273a8c646280b8'
PROGRAM = r'''
import errno,hashlib,json,sys,tempfile
from pathlib import Path
sys.path.insert(0,'/candidate')
from sbom_creator import publication as p
assert str(Path(p.__file__)).startswith('/candidate/')
observed={f.relative_to('/candidate').as_posix():hashlib.sha256(f.read_bytes()).hexdigest()
    for f in sorted(Path('/candidate').rglob('*')) if f.is_file()}
cases=[]
original=tempfile.TemporaryDirectory
with original() as work:
    root=Path(work)
    for nonempty in (False,True):
        source=root/('source-'+str(nonempty));source.mkdir()
        (source/'proof').write_bytes(b'original')
        target=root/('target-'+str(nonempty));target.mkdir()
        if nonempty:(target/'keep').write_bytes(b'foreign')
        try:p.commit_directory(source,target)
        except FileExistsError:pass
        else:raise AssertionError('existing target replaced')
        assert (source/'proof').read_bytes()==b'original'
        assert sorted(f.name for f in target.iterdir())==(['keep'] if nonempty else [])
        cases.append('no-replace-'+('nonempty' if nonempty else 'empty'))
    source=root/'success';source.mkdir();(source/'proof').write_bytes(b'committed')
    target=root/'published';p.commit_directory(source,target)
    assert not source.exists() and (target/'proof').read_bytes()==b'committed'
    cases.append('atomic-positive')
    class CleanupDenied:
        def __init__(self,**kw):self.inner=original(**kw);self.name=self.inner.name
        def cleanup(self):
            self.inner.cleanup()
            raise PermissionError(errno.EACCES,'secret-do-not-export')
    p.tempfile.TemporaryDirectory=CleanupDenied
    try:
        state=p.PublicationState()
        try:
            with p.staging_directory(root,state):
                state.mark('convert_final','final.cdx.json')
                raise RuntimeError('secret-do-not-export')
        except RuntimeError:pass
        else:raise AssertionError('primary failure lost')
        assert state.failure['error_type']=='RuntimeError'
        assert state.details()['cleanup_error_code']=='PUBLICATION_PERMISSION_DENIED'
        cases.append('primary-failure-preserved-through-cleanup')
        state=p.PublicationState()
        final=root/'post-cleanup-final'
        try:
            with p.staging_directory(root,state) as work:
                staged=work/'result';staged.mkdir();(staged/'proof').write_bytes(b'valid')
                state.mark('commit_directory');p.commit_directory(staged,final);state.committed=True
        except PermissionError as error:state.capture(error)
        else:raise AssertionError('cleanup failure suppressed')
        assert (final/'proof').read_bytes()==b'valid'
        assert state.details()['publication_operation']=='cleanup_staging'
        assert state.details()['publication_committed'] is True
        cases.append('post-commit-cleanup-truth')
    finally:p.tempfile.TemporaryDirectory=original
report={'status':'passed','cases':cases,'network':'none','source_project_read':False,
    'scanner_publisher_or_oracle_called':False,'skips':0,'source_sha256':observed,
    'program_sha256':hashlib.sha256(Path('/harness.py').read_bytes()).hexdigest()}
assert 'secret-do-not-export' not in json.dumps(report)
print(json.dumps(report))
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve every native attempt')
    snapshot=OUTPUT/'executed-source'
    shutil.copytree(ROOT/'src/sbom_creator',snapshot/'sbom_creator',
        ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    (OUTPUT/'program.py').write_bytes(PROGRAM.encode())
    (OUTPUT/'executed-driver.py').write_bytes(Path(__file__).read_bytes())
    sources={p.relative_to(snapshot).as_posix():sha(p) for p in sorted(snapshot.rglob('*')) if p.is_file()}
    write(OUTPUT/'freeze.json',{'image':IMAGE,'source_sha256':sources,
        'program_sha256':sha(OUTPUT/'program.py'),'driver_sha256':sha(__file__),
        'oracle_read':False,'scanners_called':False,'network':'none'})
    command=['docker','run','--rm','--pull=never','--network=none','--read-only','--user=10001:10001',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--cpus=1','--pids-limit=64',
        '--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777','--env','TMPDIR=/tmp',
        '--mount',f'type=bind,src={snapshot},dst=/candidate,readonly',
        '--mount',f'type=bind,src={OUTPUT / "program.py"},dst=/harness.py,readonly',
        '--entrypoint=python',IMAGE,'-B','/harness.py']
    env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','SYSTEMDRIVE',
        'PATH','PATHEXT','TEMP','TMP','PROGRAMFILES','PROGRAMDATA','APPDATA','LOCALAPPDATA','ALLUSERSPROFILE'}}
    result=subprocess.run(command,env=env,text=True,capture_output=True,timeout=60,check=False)
    (OUTPUT/'stdout.log').write_text(result.stdout,encoding='utf-8')
    (OUTPUT/'stderr.log').write_text(result.stderr,encoding='utf-8')
    write(OUTPUT/'run.json',{'exit_code':result.returncode,'command':command})
    result.check_returncode()
    report=json.loads(result.stdout)
    assert report['source_sha256']==sources and len(sources)==49
    assert report['program_sha256']==sha(OUTPUT/'program.py')
    assert all(sha(ROOT/'src'/name)==digest for name,digest in sources.items())
    write(OUTPUT/'report.json',report)
    print('PASS: five native publication/cleanup contracts,49 source hashes')


if __name__=='__main__':
    main()


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

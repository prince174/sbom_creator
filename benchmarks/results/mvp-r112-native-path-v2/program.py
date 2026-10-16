
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

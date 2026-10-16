
import hashlib,json,os,pathlib,shutil,tempfile
import sbom_creator
from sbom_creator.acquire import Settings
assert os.geteuid()==10001 and not pathlib.Path('/var/run/docker.sock').exists()
settings=Settings.from_env()
assert all(os.environ[k]=='/workspace' for k in ('TMPDIR','TMP','TEMP'))
assert tempfile.gettempdir()=='/workspace'
with tempfile.NamedTemporaryFile(prefix='default-process-temp-') as f:
    f.write(b'probe');f.flush();assert pathlib.Path(f.name).parent==pathlib.Path('/workspace')
for directory in (settings.trivy_cache_dir,settings.image_temp_dir):
    p=pathlib.Path(directory);assert p.is_relative_to('/workspace');p.mkdir(exist_ok=True,parents=True)
    probe=p/'write-probe';probe.write_text('probe');probe.unlink()
assert shutil.disk_usage('/tmp').total==512*1024**2
try:pathlib.Path('/home/sbom/not-writable').write_text('blocked')
except OSError:home_read_only=True
else:raise AssertionError('Home unexpectedly writable')
package=pathlib.Path(sbom_creator.__file__).parent
hashes={str(p.relative_to(package)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
print(json.dumps({'status':'passed','uid':os.geteuid(),'process_temp':tempfile.gettempdir(),'cache':settings.trivy_cache_dir,'image_temp':settings.image_temp_dir,'tmpfs_bytes':shutil.disk_usage('/tmp').total,'workspace_defaults_writable':True,'home_read_only':home_read_only,'installed_source_hashes':hashes,'tools_sha256':{name:hashlib.sha256(pathlib.Path(shutil.which(name)).read_bytes()).hexdigest() for name in ('syft','trivy','crane')},'test_boundary':'Default scratch/configuration and source/tool equality only; full Micro pipeline is separately measured on same package with /workspace/process-temp'}))

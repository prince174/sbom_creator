
import hashlib,inspect,json,os,pathlib,shutil,tempfile
import sbom_creator
from sbom_creator.acquire import Settings
from sbom_creator.image_java import runtime
assert os.geteuid()==10001 and not pathlib.Path('/var/run/docker.sock').exists()
settings=Settings.from_env()
assert settings.java_nested_windows is False
assert inspect.signature(runtime.corroborate).parameters['nested_windows'].default is False
assert runtime.JarFiles.__module__.endswith('.seekable_jar_evidence')
assert runtime.StoredJarFiles.__module__.endswith('.stored_jar_evidence')
os.environ['SBOM_JAVA_NESTED_WINDOWS']='true';assert Settings.from_env().java_nested_windows is True
os.environ['SBOM_JAVA_NESTED_WINDOWS']='false';assert Settings.from_env().java_nested_windows is False
os.environ['SBOM_JAVA_NESTED_WINDOWS']='invalid'
try:Settings.from_env()
except ValueError:invalid_flag_rejected=True
else:raise AssertionError('Invalid experimental selector accepted')
del os.environ['SBOM_JAVA_NESTED_WINDOWS']
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
print(json.dumps({'status':'passed','uid':os.geteuid(),'nested_windows_default':settings.java_nested_windows,'explicit_experimental_true_parses':True,'invalid_flag_rejected':invalid_flag_rejected,'default_reader_module':runtime.JarFiles.__module__,'experimental_reader_module':runtime.StoredJarFiles.__module__,'process_temp':tempfile.gettempdir(),'cache':settings.trivy_cache_dir,'image_temp':settings.image_temp_dir,'tmpfs_bytes':shutil.disk_usage('/tmp').total,'workspace_defaults_writable':True,'home_read_only':home_read_only,'installed_source_hashes':hashes,'tools_sha256':{name:hashlib.sha256(pathlib.Path(shutil.which(name)).read_bytes()).hexdigest() for name in ('syft','trivy','crane')},'test_boundary':'Installed selector/default scratch/configuration; experimental full Micro pipeline measured separately on byte-identical stored reader. No new full pipeline or oracle run.'}))

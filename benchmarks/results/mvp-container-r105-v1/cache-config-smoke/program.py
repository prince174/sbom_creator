
import hashlib,json,os,pathlib
import sbom_creator
from sbom_creator.acquire import Settings
settings=Settings.from_env()
assert os.geteuid()==10001
assert settings.trivy_cache_dir=='/workspace/trivy-cache'
assert settings.image_temp_dir=='/workspace/image-cache'
for directory in (settings.trivy_cache_dir,settings.image_temp_dir):
    root=pathlib.Path(directory);root.mkdir(parents=True,exist_ok=True)
    probe=root/'writable-probe';probe.write_text('probe');probe.unlink()
try:pathlib.Path('/home/sbom/cannot-write').write_text('blocked')
except OSError:home_read_only=True
else:raise AssertionError('Image home unexpectedly writable')
db=pathlib.Path(settings.trivy_cache_dir)/'java-db'
assert (db/'trivy-java.db').is_file()
try:(db/'readonly-probe').write_text('blocked')
except OSError:database_read_only=True
else:raise AssertionError('Public Java DB mount unexpectedly writable')
package=pathlib.Path(sbom_creator.__file__).parent
hashes={str(p.relative_to(package)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
print(json.dumps({'status':'passed','uid':os.geteuid(),'configured_cache':settings.trivy_cache_dir,'configured_image_temp':settings.image_temp_dir,'workspace_paths_writable':True,'home_read_only':home_read_only,'public_database_read_only':database_read_only,'database_bytes':(db/'trivy-java.db').stat().st_size,'java_backend_default':settings.java_backend,'installed_source_hashes':hashes,'test_boundary':'Default ENV paths and filesystem permissions. Cold network download is not exercised; code/payload smoke reused from identical installed package hashes.'}))

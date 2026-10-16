
import hashlib, importlib.metadata, json, os, pathlib, shutil, subprocess, time
import sbom_creator
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze
from sbom_creator.validation import validate_cyclonedx

root = pathlib.Path('/workspace')
assert os.geteuid() == 10001
assert not pathlib.Path('/var/run/docker.sock').exists()
try:
    pathlib.Path('/root-write-probe').write_text('blocked')
except OSError:
    root_read_only = True
else:
    raise AssertionError('Container root filesystem is writable')
package = pathlib.Path(sbom_creator.__file__).parent
hashes = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(package.rglob('*')) if p.is_file()
          and '__pycache__' not in p.parts and p.suffix != '.pyc'}
tools = {name: subprocess.check_output(command, text=True).strip() for name, command in {
    'syft': ['syft', 'version', '-o', 'json'],
    'trivy': ['trivy', 'version', '--format', 'json'],
    'crane': ['crane', 'version']}.items()}
facts = {'uid': os.geteuid(), 'root_read_only': root_read_only,
         'docker_socket_present': False, 'package_path': str(package),
         'installed_source_hashes': hashes, 'tool_versions': tools,
         'python_packages': {d.metadata['Name']: d.version for d in importlib.metadata.distributions()},
         'tool_sha256': {name: hashlib.sha256(pathlib.Path(shutil.which(name)).read_bytes()).hexdigest()
                         for name in ('syft', 'trivy', 'crane')}}
(root/'environment.json').write_text(json.dumps(facts, indent=2)+'\n')
settings = Settings(registry_hosts=(os.environ['SMOKE_REGISTRY'],),
    image_archive='/inputs/image.tar', trivy_cache_dir='/workspace/trivy-cache',
    image_temp_dir='/workspace/image-cache', java_backend='disabled')
started = time.monotonic()
try:
    summary = analyze(None, None, os.environ['SMOKE_IMAGE'], root/'analysis', settings)
except Exception as error:
    (root/'smoke-result.json').write_text(json.dumps({'status': 'failed',
        'error_type': type(error).__name__, 'elapsed_seconds': time.monotonic()-started}, indent=2)+'\n')
    raise
for filename in ('final.cdx.json', 'os.cdx.json', 'full.cdx.json'):
    validate_cyclonedx(json.loads((root/'analysis'/filename).read_text()))
provenance = json.loads((root/'analysis/provenance.json').read_text())
assert provenance['source_kind'] == 'not-provided'
assert provenance['image']['acquisition'] == 'archive'
assert provenance['image']['java_image_status'] == 'corroborated'
assert (root/'analysis/image-identity-audit.json').is_file()
assert (root/'analysis/image-peer.cdx.json').is_file()
assert (root/'analysis/image-original.syft.json').is_file()
assert summary['final_count'] > 0
result = {'status': 'passed', 'elapsed_seconds': round(time.monotonic()-started, 3),
          'summary': summary, 'source_kind': provenance['source_kind'],
          'java_image_status': provenance['image']['java_image_status'],
          'image_config_digest': provenance['image']['image_config_digest'],
          'output_hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in sorted((root/'analysis').iterdir()) if p.is_file()}}
(root/'smoke-result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))


import hashlib, json, os, pathlib, time
import sbom_creator
from sbom_creator import acquire, build_backend, payload, pipeline, scanner
from sbom_creator.acquire import Settings
from sbom_creator.image_java import runtime, java_database_cache
from sbom_creator.validation import validate_cyclonedx

root = pathlib.Path('/workspace')
assert os.geteuid() == 10001 and not pathlib.Path('/var/run/docker.sock').exists()
assert not any(root.iterdir()), 'One new native workspace volume is required'
assert not any(os.environ.get(name) for name in (
    'SBOM_API_TOKEN','SBOM_API_TOKEN_FILE','SBOM_REGISTRY_USERNAME','SBOM_REGISTRY_PASSWORD',
    'SBOM_REGISTRY_USERNAME_FILE','SBOM_REGISTRY_PASSWORD_FILE','OPENAI_API_KEY','GITHUB_TOKEN',
    'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'))
try:
    pathlib.Path('/root-write-probe').write_text('blocked')
except OSError:
    pass
else:
    raise AssertionError('Root filesystem must be read only')
package = pathlib.Path(sbom_creator.__file__).parent
installed = {path.relative_to(package).as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(package.rglob('*')) if path.is_file()
             and '__pycache__' not in path.parts and path.suffix != '.pyc'}
assert len(installed) == 49 and installed == json.loads(os.environ['R113_PACKAGE_HASHES'])
names = ('source.syft.json','image.syft.json','provenance.json')
input_hashes = {name:hashlib.sha256((pathlib.Path('/inputs')/name).read_bytes()).hexdigest() for name in names}
assert input_hashes == json.loads(os.environ['R113_INPUT_HASHES'])
source, image, provenance = (json.loads((pathlib.Path('/inputs')/name).read_bytes()) for name in names)
assert not source['artifacts'] and not source.get('artifactRelationships')
assert provenance['source_kind'] == 'not-provided'
assert provenance.get('request',{}).get('repository_url') is None
assert provenance.get('request',{}).get('commit') is None
original_payload = provenance['image']['payload_evidence']
assert any(fact.get('payload_kind') == 'declared_type_surface' for fact in original_payload.values())
defaults = Settings.from_env()
assert defaults.java_archive_components is True and defaults.java_nested_windows is False
assert defaults.java_backend == 'disabled'
assert 'SBOM_JAVA_ARCHIVE_COMPONENTS' not in os.environ and 'SBOM_JAVA_NESTED_WINDOWS' not in os.environ

def forbidden(*_args, **_kwargs):
    raise AssertionError('Only cached publication and pinned Syft conversion are permitted')
for module, name in ((acquire,'checkout'),(build_backend,'resolve'),(payload,'collect'),
    (scanner,'scan_source'),(scanner,'scan_image'),(scanner,'collect_payload'),
    (pipeline,'checkout'),(pipeline,'scan_source'),(pipeline,'scan_image'),(pipeline,'resolve_java'),
    (runtime,'acquire'),(runtime,'peer'),(runtime,'analyze'),(runtime,'corroborate'),
    (runtime,'ensure_database'),(runtime,'PublicJavaHashLookup'),(java_database_cache,'ensure')):
    setattr(module,name,forbidden)
original_syft, conversions = scanner._syft, []
def convert_only(args, settings, *, output):
    assert args[0] == 'convert'
    conversions.append('convert')
    return original_syft(args, settings, output=output)
scanner._syft = convert_only
facts = {'uid':os.geteuid(),'root_read_only':True,'docker_socket_present':False,
    'installed_source_hashes':installed,'input_sha256':input_hashes,
    'executed_program_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    'java_archive_components_default':defaults.java_archive_components,
    'java_nested_windows_default':defaults.java_nested_windows,'feature_overrides_absent':True,
    'cached_payload_mapping':True,'fresh_scans':False,'fresh_physical_reads':False,'source_project_input':False,
    'reference_accessed':False,'database_read_or_downloaded':False}
(root/'environment.json').write_text(json.dumps(facts,indent=2)+'\n')
started = time.monotonic()
result = {'status':'failed','reference_accessed':False,'new_accuracy_measurement':False}
try:
    summary = pipeline.publish_catalogs(source,image,root/'analysis',defaults,pipeline.rules_assessor,provenance)
    assert conversions == ['convert'] and summary['policy_version'] == 'image-evidence-and-payload-v4'
    for view in ('final','os','full'):
        validate_cyclonedx(json.loads((root/'analysis'/(view+'.cdx.json')).read_bytes()))
    actual = json.loads((root/'analysis/provenance.json').read_bytes())['image']['payload_evidence']
    assert actual == original_payload
    assert not pathlib.Path(defaults.trivy_cache_dir).exists()
    assert input_hashes == {name:hashlib.sha256((pathlib.Path('/inputs')/name).read_bytes()).hexdigest() for name in names}
    result.update(status='passed',summary=summary,conversion_calls=len(conversions),
        all_cached_payload_facts_unchanged=True,
        declared_type_witness_count=sum(f.get('payload_kind')=='declared_type_surface' for f in actual.values()),
        output_sha256={path.name:hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted((root/'analysis').iterdir()) if path.is_file()})
except Exception as error:
    result.update(error=pipeline.error_fields(error,'publication'))
    raise
finally:
    result['publisher_seconds'] = time.monotonic()-started
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))

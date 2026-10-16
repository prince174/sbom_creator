"""POST-ONLY primary owner proof for the immutable literal reactor recipe.

This is intentionally an eligibility check for an existing controlled build,
not a general Dockerfile interpreter or classifier identity rule.
"""
import hashlib
import re
import xml.etree.ElementTree as ET

from audit_reactor_scope_r107 import component_hash
from compare_java_js import all_components, coord
from packageurl import PackageURL

SIMPLE = re.compile(r'[A-Za-z0-9_.-]+')
MODULE = re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*')
NS = {'m': 'http://maven.apache.org/POM/4.0.0'}
METHOD = 'immutable_literal_recipe_effective_native_cdx_canonical_properties_full_sha256'


def one(root, path, default=None):
    values = root.findall(path, NS)
    if not values:
        return default
    if len(values) != 1 or values[0].text is None:
        raise ValueError('AMBIGUOUS_EFFECTIVE_MODEL')
    return values[0].text.strip()


def metadata_gav(raw, member_path):
    if not raw or len(raw) > 32 * 1024:
        raise ValueError('PRIMARY_METADATA_BUDGET')
    text = raw.decode('ascii')
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        # Unrelated literal value escapes (e.g. buildTime's escaped colon) do
        # not change identity fields. Continuations/escaped keys are rejected.
        if len(line) - len(line.rstrip('\\')) & 1 or '=' not in line:
            raise ValueError('UNSUPPORTED_PRIMARY_PROPERTIES')
        key, value = (part.strip() for part in line.split('=', 1))
        if '\\' in key or key in values or not key:
            raise ValueError('AMBIGUOUS_PRIMARY_PROPERTIES')
        values[key] = value
    gav = tuple(values.get(key, '') for key in ('groupId', 'artifactId', 'version'))
    if any(not SIMPLE.fullmatch(value) for value in gav):
        raise ValueError('NONLITERAL_PRIMARY_GAV')
    if member_path != f'META-INF/maven/{gav[0]}/{gav[1]}/pom.properties':
        raise ValueError('NONCANONICAL_PRIMARY_METADATA_PATH')
    return gav


def dependency_names(native, bom):
    result = set()
    pending = list(native.get('children', []))
    while pending:
        node = pending.pop()
        pending.extend(node.get('children', []))
        if node.get('type') != 'jar':
            continue
        artifact, version, classifier = node['artifactId'], node['version'], node.get('classifier', '')
        if any(not SIMPLE.fullmatch(value) for value in (artifact, version)) or (
                classifier and not SIMPLE.fullmatch(classifier)):
            raise ValueError('NONLITERAL_DEPENDENCY_FILENAME')
        result.add(artifact + '-' + version + ('-' + classifier if classifier else '') + '.jar')
    for component in all_components(bom):
        if not component.get('purl'):
            continue
        purl = PackageURL.from_string(component['purl'])
        if purl.type != 'maven' or purl.qualifiers.get('type', 'jar') != 'jar':
            continue
        classifier = purl.qualifiers.get('classifier', '')
        if any(not SIMPLE.fullmatch(value or '') for value in (purl.name, purl.version)) or (
                classifier and not SIMPLE.fullmatch(classifier)):
            raise ValueError('NONLITERAL_CDX_DEPENDENCY_FILENAME')
        result.add(purl.name + '-' + purl.version + ('-' + classifier if classifier else '') + '.jar')
    return result


def attest(module, bom, native, effective_raw, dockerfile_raw, image_path,
           digest, properties_path, properties_raw):
    path, prefix = module['path'], module['image_prefix']
    if (not MODULE.fullmatch(path) or any(part in ('.', '..') for part in path.split('/'))
            or prefix != '/application/' + path + '/'):
        raise ValueError('UNSUPPORTED_PRIMARY_MODULE_PATH')
    if len(effective_raw) > 16 * 1024 * 1024 or any(
            token in effective_raw.upper() for token in (b'<!DOCTYPE', b'<!ENTITY')):
        raise ValueError('UNSUPPORTED_EFFECTIVE_XML')
    root = ET.fromstring(effective_raw)
    gav = tuple(one(root, f'm:{key}') for key in ('groupId', 'artifactId', 'version'))
    if any(not SIMPLE.fullmatch(value or '') for value in gav):
        raise ValueError('NONLITERAL_EFFECTIVE_GAV')
    owner = 'pkg:maven/' + gav[0] + '/' + gav[1] + '@' + gav[2]
    if (coord(bom['metadata']['component']) != owner or tuple(module['owner']) != gav
            or tuple(native.get(key) for key in ('groupId', 'artifactId', 'version')) != gav):
        raise ValueError('EFFECTIVE_NATIVE_CDX_OWNER_CONFLICT')
    if one(root, 'm:packaging', 'jar') != 'jar' or native.get('type') != 'jar':
        raise ValueError('PRIMARY_PACKAGING_NOT_JAR')
    final_name = one(root, 'm:build/m:finalName')
    if (not SIMPLE.fullmatch(final_name or '') or
            one(root, 'm:build/m:directory') != '/src/' + path + '/target'):
        raise ValueError('NONLITERAL_EFFECTIVE_OUTPUT_PATH')
    filename, source_path = final_name + '.jar', path + '/target/' + final_name + '.jar'
    if image_path != prefix + filename:
        raise ValueError('PRIMARY_FINAL_PATH_CONFLICT')
    if not re.fullmatch('[a-f0-9]{64}', digest):
        raise ValueError('PRIMARY_PHYSICAL_SHA256_ABSENT')
    if filename in dependency_names(native, bom) or any(
            component_hash(c) == digest for c in all_components(bom)):
        raise ValueError('DEPENDENCY_COPY_PRIMARY_COLLISION')
    if metadata_gav(properties_raw, properties_path) != gav:
        raise ValueError('PRIMARY_EMBEDDED_GAV_CONFLICT')
    dockerfile = dockerfile_raw.decode('utf-8')
    lines = dockerfile.splitlines()
    tail = (f' && mkdir -p {prefix.rstrip("/")} && cp {source_path} {prefix}'
            f' && if [ -d {path}/target/dependency ]; then find {path}/target/dependency'
            f" -name '*.jar' -exec cp {{}} {prefix} \\; ; fi")
    candidates = [line for line in lines if line.startswith('RUN ') and line.endswith(tail)]
    if len(candidates) != 1 or any(prefix in line for line in lines if line != candidates[0]):
        raise ValueError('UNSUPPORTED_OR_AMBIGUOUS_LITERAL_PRIMARY_COPY')
    line = candidates[0]
    if line.count(prefix) != 2 or 'copy-dependencies -DincludeScope=runtime' not in line:
        raise ValueError('UNSUPPORTED_PRIMARY_COPY_TAIL')
    if lines.count('WORKDIR /src') != 1 or lines.count('COPY src/ /src/') != 1:
        raise ValueError('SOURCE_RECIPE_WORKDIR_CONFLICT')
    expected_runtime = ['FROM scratch AS runtime',
                        'COPY --from=build /application /application',
                        'USER 65532:65532', 'CMD ["/not-executed-reactor-artifact-fixture"]']
    if not dockerfile.endswith('\n') or lines[-4:] != expected_runtime:
        raise ValueError('UNSUPPORTED_RUNTIME_COPY_RECIPE')
    return {'method': METHOD, 'owner': owner, 'actual_physical_sha256': digest,
            'literal_copy_source': source_path, 'literal_copy_destination': prefix,
            'effective_final_name': final_name, 'effective_build_directory': '/src/' + path + '/target',
            'dockerfile_sha256': hashlib.sha256(dockerfile_raw).hexdigest(),
            'effective_pom_sha256': hashlib.sha256(effective_raw).hexdigest(),
            'embedded_properties_path': properties_path,
            'embedded_properties_sha256': hashlib.sha256(properties_raw).hexdigest(),
            'native_and_cdx_owner_agree': True, 'dependency_copy_collision_absent': True,
            'claim': 'Controlled-build primary owner only; no shaded-identity, directness or publisher-authentication claim'}

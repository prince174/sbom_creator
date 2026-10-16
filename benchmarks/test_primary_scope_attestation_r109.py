import copy

import primary_scope_attestation_r109 as primary
import pytest


def inputs():
    module = {'path': 'nested/module', 'image_prefix': '/application/nested/module/',
              'owner': ['example.group', 'module', '1.0']}
    bom = {'metadata': {'component': {'purl': 'pkg:maven/example.group/module@1.0?type=jar'}},
           'components': []}
    native = {'groupId': 'example.group', 'artifactId': 'module', 'version': '1.0',
              'type': 'jar', 'children': []}
    xml = b'''<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>example.group</groupId><artifactId>module</artifactId><version>1.0</version>
    <build><directory>/src/nested/module/target</directory><finalName>module-1.0</finalName></build>
    </project>'''
    docker = b'''FROM buildbase AS build
WORKDIR /src
COPY src/ /src/
RUN mvn copy-dependencies -DincludeScope=runtime && mkdir -p /application/nested/module && cp nested/module/target/module-1.0.jar /application/nested/module/ && if [ -d nested/module/target/dependency ]; then find nested/module/target/dependency -name '*.jar' -exec cp {} /application/nested/module/ \\; ; fi
FROM scratch AS runtime
COPY --from=build /application /application
USER 65532:65532
CMD ["/not-executed-reactor-artifact-fixture"]
'''
    return [module, bom, native, xml, docker, '/application/nested/module/module-1.0.jar',
            'a' * 64, 'META-INF/maven/example.group/module/pom.properties',
            b'groupId=example.group\nartifactId=module\nversion=1.0\nbuildTime=2026-09-21T18\\:35\\:37Z\n']


def test_positive_requires_recipe_model_metadata_and_physical_hash():
    result = primary.attest(*inputs())
    assert result['owner'] == 'pkg:maven/example.group/module@1.0'
    assert result['literal_copy_source'] == 'nested/module/target/module-1.0.jar'
    assert result['literal_copy_destination'] == '/application/nested/module/'
    assert result['method'] == primary.METHOD
    assert result['native_and_cdx_owner_agree'] and result['dependency_copy_collision_absent']


@pytest.mark.parametrize('index,value,reason', [
    (5, '/application/wrong/module-1.0.jar', 'PRIMARY_FINAL_PATH_CONFLICT'),
    (6, 'not-a-hash', 'PRIMARY_PHYSICAL_SHA256_ABSENT'),
    (7, 'pom.properties', 'NONCANONICAL_PRIMARY_METADATA_PATH'),
    (8, b'groupId=other\nartifactId=module\nversion=1.0\n', 'NONCANONICAL_PRIMARY_METADATA_PATH'),
    (8, b'groupId=example.group\nartifactId=module\nversion=1.0\nversion=2\n', 'AMBIGUOUS_PRIMARY_PROPERTIES'),
    (8, b'groupId=example.group\nartifactId=module\nversion=${revision}\n', 'NONLITERAL_PRIMARY_GAV'),
])
def test_no_primary_from_filename_or_conflicting_metadata(index, value, reason):
    data = inputs()
    data[index] = value
    with pytest.raises(ValueError, match=reason):
        primary.attest(*data)


def test_native_cdx_effective_agreement_required():
    data = inputs()
    data[2]['version'] = '2.0'
    with pytest.raises(ValueError, match='EFFECTIVE_NATIVE_CDX_OWNER_CONFLICT'):
        primary.attest(*data)


def test_canonical_other_gav_metadata_still_conflicts_with_owner():
    data = inputs()
    data[7] = 'META-INF/maven/other/module/pom.properties'
    data[8] = b'groupId=other\nartifactId=module\nversion=1.0\n'
    with pytest.raises(ValueError, match='PRIMARY_EMBEDDED_GAV_CONFLICT'):
        primary.attest(*data)
    data = inputs()
    data[1]['metadata']['component']['purl'] = 'pkg:maven/other/module@1.0'
    with pytest.raises(ValueError, match='EFFECTIVE_NATIVE_CDX_OWNER_CONFLICT'):
        primary.attest(*data)


@pytest.mark.parametrize('old,new', [
    (b'nested/module/target/module-1.0.jar', b'nested/module/target/another.jar'),
    (b'COPY --from=build /application /application', b'COPY --from=other /application /application'),
    (b'USER 65532:65532', b'RUN cp overwrite /application/nested/module/module-1.0.jar'),
])
def test_literal_copy_recipe_does_not_accept_another_source_or_overwrite(old, new):
    data = inputs()
    data[4] = data[4].replace(old, new)
    with pytest.raises(ValueError):
        primary.attest(*data)


def test_later_dependency_basename_collision_rejects_owner():
    data = inputs()
    data[2]['children'] = [{'groupId': 'other.group', 'artifactId': 'module',
                            'version': '1.0', 'type': 'jar'}]
    with pytest.raises(ValueError, match='DEPENDENCY_COPY_PRIMARY_COLLISION'):
        primary.attest(*data)
    data = inputs()
    data[1]['components'] = [{'purl': 'pkg:maven/other.group/module@1.0?type=jar'}]
    with pytest.raises(ValueError, match='DEPENDENCY_COPY_PRIMARY_COLLISION'):
        primary.attest(*data)


def test_cdx_dependency_hash_collision_rejects_even_another_basename():
    data = inputs()
    data[1]['components'] = [{'purl': 'pkg:maven/other.group/another@2',
        'hashes': [{'alg': 'SHA-256', 'content': 'a' * 64}]}]
    with pytest.raises(ValueError, match='DEPENDENCY_COPY_PRIMARY_COLLISION'):
        primary.attest(*data)


@pytest.mark.parametrize('replacement', [
    b'<finalName>${artifactId}</finalName>',
    b'<finalName>../../elsewhere</finalName>',
    b'<finalName>module-1.0</finalName><finalName>other</finalName>',
])
def test_effective_output_must_be_one_concrete_path(replacement):
    data = inputs()
    data[3] = data[3].replace(b'<finalName>module-1.0</finalName>', replacement)
    with pytest.raises(ValueError):
        primary.attest(*data)


def test_xml_entities_and_properties_continuation_not_interpreted():
    data = inputs()
    data[3] = b'<!DOCTYPE project []>' + data[3]
    with pytest.raises(ValueError, match='UNSUPPORTED_EFFECTIVE_XML'):
        primary.attest(*data)
    data = inputs()
    data[8] = data[8].replace(b'groupId=example.group\n', b'groupId=example.\\\ngroup\n')
    with pytest.raises(ValueError, match='UNSUPPORTED_PRIMARY_PROPERTIES'):
        primary.attest(*data)


def test_function_does_not_mutate_controlled_inputs():
    original = inputs()
    before = copy.deepcopy(original)
    primary.attest(*original)
    assert original == before

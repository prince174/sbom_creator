"""Complete physical archive presence is distinct from executable payload."""
import copy
import hashlib
import random
import stat
import time
import zipfile

import pytest
from pydantic import ValidationError
from test_nested_jar_reuse import fixture, jar, mutation
from test_public_java_hash_identity import database, digest

from sbom_creator import core
from sbom_creator.acquire import Settings
from sbom_creator.image_java import archive_component_evidence as evidence
from sbom_creator.image_java.runtime import corroborate
from sbom_creator.service import Request

PURL = 'pkg:maven/example/core@1'
PROPERTIES = 'META-INF/maven/example/core/pom.properties'
BODY = b'groupId=example\nartifactId=core\nversion=1\n'


def inputs(tmp_path, entries=None, *, nested=None, compression=zipfile.ZIP_STORED):
    nested = nested if nested is not None else jar(entries or [(PROPERTIES, BODY)])
    outer = jar([('lib/core.jar', nested)], compression)
    image, peer, archive = fixture(tmp_path, outers=[outer])
    return image, peer, archive, nested


def run(image, peer, archive, tmp_path, **kwargs):
    adapted, physical, envelope, audit = corroborate(image, archive, peer, temporary=tmp_path,
                                                    archive_components=True, **kwargs)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    return adapted, physical, envelope, audit, result


def included(result):
    return {artifact['purl'] for artifact in result['selected_syft']['artifacts']}


def test_actual_complete_metadata_only_archive_has_separate_presence_not_fake_payload(tmp_path):
    image, peer, archive, nested = inputs(tmp_path)
    adapted, physical, envelope, audit, result = run(image, peer, archive, tmp_path)
    assert included(result) == {PURL}
    assert physical['core-0']['status'] == 'unconfirmed'
    assert not physical['core-0'].get('path')
    proof = envelope['archive_presence']['core-0']
    assert proof['sha256'] == hashlib.sha256(nested).hexdigest()
    assert proof['sha1'] == hashlib.sha1(nested).hexdigest()
    assert proof['bytes'] == len(nested)
    assert proof['nested_crc_verified'] and proof['chain_verified']
    assert proof['identity_method'] == 'canonical_maven_properties'
    assert adapted['artifacts'][0]['foundBy'] == image['artifacts'][0]['foundBy']
    assert adapted['artifacts'][0]['purl'] == PURL
    assert audit['binding']['archive_components'][0]['status'] == 'BOUND_ARCHIVE_COMPONENT'
    assert result['coverage']['policy_version'] == 'image-delivered-archive-v7'
    fact = result['decisions'][0]['evidence'][0]
    assert fact['presence_kind'] == 'verified_archive_component'
    assert fact['payload']['status'] == 'unconfirmed'
    assert fact['archive_presence']['status'] == 'confirmed'
    assert fact['archive_identity_binding']['status'] == 'BOUND'
    assert fact['identity_binding']['status'] == 'UNKNOWN'


def test_explicit_legacy_and_nested_only_policies_keep_metadata_only_archive_unknown(tmp_path):
    assert Settings().java_archive_components
    assert not Settings(java_archive_components=False).java_archive_components
    image, peer, archive, _ = inputs(tmp_path)
    for nested in (False, True):
        adapted, physical, envelope, _ = corroborate(image, archive, peer, temporary=tmp_path, nested_windows=nested)
        result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
        assert not included(result)
        assert 'archive_presence' not in envelope
        assert physical['core-0']['status'] == 'unconfirmed'


@pytest.mark.parametrize('entries', [
    [('pom.xml', b'<project><groupId>example</groupId><artifactId>core</artifactId><version>1</version></project>')],
    [('package.json', b'{"name":"core","version":"1"}')],
    [('META-INF/MANIFEST.MF', b'Implementation-Title: core\nImplementation-Version: 1\n')],
    [('META-INF/maven/other/core/pom.properties', BODY)],
    [(PROPERTIES, b'groupId=wrong\nartifactId=core\nversion=1\n')],
    [(PROPERTIES, b'groupId=example\nartifactId=wrong\nversion=1\n')],
    [(PROPERTIES, b'groupId=example\nartifactId=core\nversion=2\n')],
    [(PROPERTIES, BODY+b'version=1\n')],
    [(PROPERTIES, BODY+b'version=2\n')],
    [(PROPERTIES, BODY.replace(b'example', b'exam\\u0070le'))],
    [(PROPERTIES, BODY.replace(b'example', b'exam\\\nple'))],
    [(PROPERTIES, BODY.replace(b'version=1', b'version=${v}'))],
    [(PROPERTIES, BODY.replace(b'version=1', b'version=1.*'))],
    [(PROPERTIES, BODY.replace(b'version=1', b'version='))],
    [(PROPERTIES, BODY+b'\x00')],
    [(PROPERTIES, BODY+b'\xff')],
    [(PROPERTIES, BODY), ('META-INF/maven/other/other/pom.properties', b'groupId=other\nartifactId=other\nversion=1\n')],
])
def test_unsupported_or_conflicting_metadata_is_not_component_identity(tmp_path, entries):
    image, peer, archive, _ = inputs(tmp_path, entries)
    _, physical, envelope, _, result = run(image, peer, archive, tmp_path)
    assert not included(result)
    assert not envelope['archive_presence']
    assert physical['core-0']['status'] == 'unconfirmed'


def test_duplicate_properties_zip_member_is_not_unique_identity(tmp_path):
    with pytest.warns(UserWarning, match='Duplicate name'):
        image, peer, archive, _ = inputs(tmp_path, [(PROPERTIES, BODY), (PROPERTIES, BODY)])
    assert not included(run(image, peer, archive, tmp_path)[-1])


@pytest.mark.parametrize('path', ['../META-INF/maven/example/core/pom.properties',
    '/META-INF/maven/example/core/pom.properties', 'META-INF/maven/example/../core/pom.properties'])
def test_noncanonical_properties_zip_paths_are_not_presence(tmp_path, path):
    image, peer, archive, _ = inputs(tmp_path, [(path, BODY)])
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_symlink_properties_member_is_not_read_as_identity(tmp_path):
    member = zipfile.ZipInfo(PROPERTIES)
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    image, peer, archive, _ = inputs(tmp_path, [(member, BODY)])
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_oversized_properties_remains_unknown(tmp_path):
    raw = BODY+b'#'+random.Random(108).randbytes(evidence.MAX_METADATA)
    image, peer, archive, _ = inputs(tmp_path, [(PROPERTIES, raw)])
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_metadata_inflate_ratio_is_not_relaxed_for_archive_presence(tmp_path):
    nested = jar([(PROPERTIES, BODY+b'#'+b'x'*25_000)], zipfile.ZIP_DEFLATED)
    image, peer, archive, _ = inputs(tmp_path, nested=nested)
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_truncated_nested_zip_is_not_complete_archive_presence(tmp_path):
    nested = jar([(PROPERTIES, BODY)])[:-5]
    image, peer, archive, _ = inputs(tmp_path, nested=nested)
    assert not included(run(image, peer, archive, tmp_path)[-1])


@pytest.mark.parametrize('field,value', [('flags', 1), ('method', 8), ('crc', 0), ('compressed_size', 1), ('size', 1)])
def test_broken_containing_stored_header_never_establishes_component(tmp_path, field, value):
    nested = jar([(PROPERTIES, BODY)])
    outer = mutation(jar([('lib/core.jar', nested)]), field, value)
    image, peer, archive = fixture(tmp_path, outers=[outer])
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_same_directory_changed_actual_properties_body_rejects_crc(tmp_path):
    good = jar([(PROPERTIES, BODY)])
    bad = good.replace(b'version=1', b'version=2', 1)
    assert bad[bad.index(b'PK\x01\x02'):] == good[good.index(b'PK\x01\x02'):]
    image, peer, archive, _ = inputs(tmp_path, nested=bad)
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_compressed_spool_chain_does_not_claim_physical_window_proof(tmp_path):
    image, peer, archive, _ = inputs(tmp_path, compression=zipfile.ZIP_DEFLATED)
    _, _, envelope, _, result = run(image, peer, archive, tmp_path)
    assert not included(result)
    assert not envelope['archive_presence']


@pytest.mark.parametrize('binding', ['peer_layer', 'peer_path', 'artifact_access', 'peer_identity'])
def test_complete_bytes_cannot_repair_different_path_layer_or_identity(tmp_path, binding):
    image, peer, archive, _ = inputs(tmp_path)
    if binding == 'peer_layer':
        peer['components'][0]['properties'][1]['value'] = 'sha256:'+'f'*64
    elif binding == 'peer_path':
        peer['components'][0]['properties'][0]['value'] = 'different.jar/lib/core.jar'
    elif binding == 'artifact_access':
        image['artifacts'][0]['locations'][0]['accessPath'] = '/different.jar:lib/core.jar'
    else:
        peer['components'][0].update(version='2', purl='pkg:maven/example/core@2')
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_wrong_image_binding_is_rejected(tmp_path):
    image, peer, archive, _ = inputs(tmp_path)
    peer['metadata']['component']['properties'][0]['value'] = 'sha256:'+'f'*64
    with pytest.raises(ValueError, match='config identity|image binding'):
        run(image, peer, archive, tmp_path)


def test_ambiguous_peer_or_syft_package_at_exact_archive_is_unknown(tmp_path):
    image, peer, archive, _ = inputs(tmp_path)
    peer['components'].append(copy.deepcopy(peer['components'][0]))
    assert not included(run(image, peer, archive, tmp_path)[-1])
    peer['components'].pop()
    duplicate = copy.deepcopy(image['artifacts'][0])
    duplicate['id'] = 'duplicate-observation'
    image['artifacts'].append(duplicate)
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_wrong_producer_does_not_get_archive_component_trust(tmp_path):
    image, peer, archive, _ = inputs(tmp_path)
    image['artifacts'][0]['foundBy'] = 'invented-java-cataloger'
    assert not included(run(image, peer, archive, tmp_path)[-1])


def test_same_purl_confirmed_sibling_does_not_promote_unknown_archive_instance(tmp_path):
    good = jar([(PROPERTIES, BODY)])
    unknown = jar([('pom.xml', b'<project/>')])
    image, peer, archive = fixture(tmp_path, outers=[jar([('lib/core.jar', good)]),
                                                   jar([('lib/core.jar', unknown)])])
    for artifact in image['artifacts']:
        artifact['purl'] = PURL
    for component in peer['components']:
        component.update(version='1', purl=PURL)
    _, physical, envelope, _, result = run(image, peer, archive, tmp_path)
    assert {artifact['id'] for artifact in result['selected_syft']['artifacts']} == {'core-0'}
    assert set(envelope['archive_presence']) == {'core-0'}
    assert physical['core-1']['status'] == 'unconfirmed'
    unknown_fact = next(fact for row in result['decisions'] for fact in row['evidence']
                        if fact['artifact_id'] == 'core-1')
    assert unknown_fact['presence_kind'] != 'verified_archive_component'


def test_identical_archive_bytes_with_multiple_claimed_identities_stay_unknown(tmp_path):
    nested = jar([(PROPERTIES, BODY)])
    image, peer, archive = fixture(tmp_path, nested=nested)
    _, physical, envelope, audit, result = run(image, peer, archive, tmp_path)
    assert not included(result)
    assert not envelope['archive_presence']
    assert all(item['status'] == 'unconfirmed' for item in physical.values())
    assert any(row.get('reason') == 'SAME_BYTES_MULTIPLE_IDENTITIES'
               for row in audit['binding']['archive_components'])


def test_public_database_association_requires_complete_actual_nested_hash(tmp_path):
    image, peer, archive, nested = inputs(tmp_path, [('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n')])
    path = database(tmp_path/'java.db', sha1=hashlib.sha1(nested).digest(),
                    group='example', artifact='core', version='1')
    _, physical, envelope, audit, result = run(image, peer, archive, tmp_path,
        java_database=path, database_sha256=digest(path))
    assert included(result) == {PURL}
    assert physical['core-0']['status'] == 'unconfirmed'
    proof = envelope['archive_presence']['core-0']
    assert proof['sha256'] == hashlib.sha256(nested).hexdigest()
    assert proof['identity_method'] == 'public_java_db_full_sha1'
    assert proof['public_hash_association']['sha1'] == hashlib.sha1(nested).hexdigest()
    assert not proof['public_hash_association']['publisher_authenticated']
    assert 'not an independent' in audit['binding']['archive_identity_database']['lookup']


@pytest.mark.parametrize('change', ['unknown_hash', 'wrong_gav', 'wrong_type'])
def test_unmatched_public_hash_association_is_not_filename_fallback(tmp_path, change):
    image, peer, archive, nested = inputs(tmp_path, [('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n')])
    path = database(tmp_path/'java.db', sha1=(bytes(20) if change == 'unknown_hash' else hashlib.sha1(nested).digest()),
                    group='example', artifact='other' if change == 'wrong_gav' else 'core', version='1',
                    archive='aar' if change == 'wrong_type' else 'jar')
    assert not included(run(image, peer, archive, tmp_path, java_database=path,
                            database_sha256=digest(path))[-1])


def test_wrong_database_pin_does_not_create_archive_evidence(tmp_path):
    image, peer, archive, nested = inputs(tmp_path)
    path = database(tmp_path/'java.db', sha1=hashlib.sha1(nested).digest())
    with pytest.raises(ValueError, match='snapshot'):
        run(image, peer, archive, tmp_path, java_database=path, database_sha256='0'*64)


@pytest.mark.parametrize('field,value', [('archive_type', 'aar'), ('lookup', 'filename'),
    ('sha1', '0'*40), ('purl', 'pkg:maven/example/core@2'), ('database_sha256', 'bad-pin'),
    ('database_sha256', 'f'*64), ('publisher_authenticated', True), ('globally_unique_gav_proven', True)])
def test_resealed_public_association_with_wrong_method_or_identity_is_rejected(tmp_path, field, value):
    image, peer, archive, nested = inputs(tmp_path, [('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\n')])
    path = database(tmp_path/'java.db', sha1=hashlib.sha1(nested).digest(),
                    group='example', artifact='core', version='1')
    adapted, physical, envelope, _, _ = run(image, peer, archive, tmp_path,
        java_database=path, database_sha256=digest(path))
    envelope['archive_presence']['core-0']['public_hash_association'][field] = value
    envelope['archive_presence_sha256'] = core.checksum(envelope['archive_presence'])
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert not included(result)


@pytest.mark.parametrize('field,value', [('status', 'unknown'), ('kind', 'class_payload'), ('chain_verified', False),
    ('zip_crc_verified', False),
    ('path', '/other.jar'), ('layer', 'sha256:'+'f'*64), ('image_config_digest', 'sha256:'+'f'*64),
    ('virtual_path', '/other.jar:lib/core.jar'), ('sha256', 'not-a-hash'), ('sha1', 'not-a-hash'),
    ('bytes', 0), ('identity', 'pkg:maven/example/core@2'), ('identity_method', 'filename'),
    ('metadata_identity', 'pkg:maven/example/core@2'), ('nested_crc_verified', False)])
def test_resealed_malformed_archive_proof_cannot_pass_structural_gate(tmp_path, field, value):
    image, peer, archive, _ = inputs(tmp_path)
    adapted, physical, envelope, _, _ = run(image, peer, archive, tmp_path)
    envelope['archive_presence']['core-0'][field] = value
    envelope['archive_presence_sha256'] = core.checksum(envelope['archive_presence'])
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert not included(result)
    assert physical['core-0']['status'] == 'unconfirmed'


def test_stale_presence_envelope_is_rejected(tmp_path):
    image, peer, archive, _ = inputs(tmp_path)
    adapted, physical, envelope, _, _ = run(image, peer, archive, tmp_path)
    envelope['archive_presence']['core-0']['sha256'] = 'f'*64
    with pytest.raises(ValueError, match='Archive-presence envelope mismatch'):
        core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)


def test_api_request_cannot_supply_trusted_archive_proofs():
    for key in ('archive_presence', 'identity_binding_envelope', 'payload_evidence', 'java_archive_components'):
        with pytest.raises(ValidationError):
            Request(image='example.com/app@sha256:'+'a'*64, **{key: {}})


def test_warm_archive_cache_does_not_bypass_component_deadline(tmp_path):
    image, _, archive, _ = inputs(tmp_path)
    reader = evidence.JarFiles(archive, image, temporary=tmp_path)
    try:
        assert reader.component(image['artifacts'][0])['status'] == 'confirmed'
        reader.started = time.monotonic()-181
        with pytest.raises(ValueError, match='Witness job deadline'):
            reader.component(image['artifacts'][0])
    finally:
        reader.close()


def test_warm_component_hash_does_not_bypass_member_crc_read_budget(tmp_path):
    image, _, archive, _ = inputs(tmp_path)
    reader = evidence.JarFiles(archive, image, temporary=tmp_path)
    try:
        assert reader.component(image['artifacts'][0])['status'] == 'confirmed'
        assert reader.component_hashes
        reader.stats['ordinary_read_bytes'] = 128*1024**2-1
        before = reader.stats['archive_crc_read_bytes']
        with pytest.raises(ValueError, match='Archive CRC validation read budget'):
            reader.component(image['artifacts'][0])
        assert reader.stats['archive_crc_read_bytes'] == before
        assert reader.stats['ordinary_read_bytes'] == 128*1024**2-1
    finally:
        reader.close()


def test_cached_outer_and_crc_cannot_bypass_new_full_component_hash_budget(tmp_path, monkeypatch):
    image, _, archive, _ = inputs(tmp_path)
    reader = evidence.JarFiles(archive, image, temporary=tmp_path)
    try:
        assert reader.witness(image['artifacts'][0]) is None
        assert reader.file_hashes and reader.verified_stored
        assert not reader.component_hashes
        reader.stats['verification_read_bytes'] = 8*1024**3-1
        nested = reader.spools[('/app0.jar', 'lib/core.jar')].window
        source = nested.stream
        original = source.read

        def no_body_read(amount=-1):
            position = source.tell()
            end = position+amount if amount >= 0 else nested.offset+nested.size
            assert not (position < nested.offset+nested.size and end > nested.offset), 'Unbudgeted component hash read'
            return original(amount)

        monkeypatch.setattr(source, 'read', no_body_read)
        with pytest.raises(ValueError, match='Content verification read budget'):
            reader.component(image['artifacts'][0])
        assert reader.stats['verification_read_bytes'] == 8*1024**3-1
        assert reader.stats['archive_hash_verifications'] == 0
    finally:
        reader.close()


def test_corrupt_nonidentity_member_cannot_use_valid_properties_as_presence(tmp_path):
    good = jar([(PROPERTIES, BODY), ('META-INF/LICENSE', b'copyright proof')])
    bad = good.replace(b'copyright proof', b'corrupted proof', 1)
    assert bad[bad.index(b'PK\x01\x02'):] == good[good.index(b'PK\x01\x02'):]
    image, peer, archive, _ = inputs(tmp_path, nested=bad)
    _, physical, envelope, _, result = run(image, peer, archive, tmp_path)
    assert not included(result)
    assert not envelope['archive_presence']
    assert physical['core-0']['status'] == 'unconfirmed'

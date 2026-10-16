"""R110 release-selector adoption and failure boundaries; no build oracle."""
import copy
import hashlib
import json
from dataclasses import replace

import pytest
import test_pipeline
from test_archive_component_presence import PURL, inputs
from test_public_java_hash_identity import database, digest

from sbom_creator import core, scanner
from sbom_creator.acquire import Settings
from sbom_creator.image_java import runtime
from sbom_creator.image_java.public_hash_identity import PublicJavaHashLookup
from sbom_creator.pipeline import publish_catalogs
from sbom_creator.validation import validate_cyclonedx

real_catalogs = test_pipeline.real_catalogs


def test_archive_components_are_release_default_in_dataclass_and_environment(monkeypatch):
    monkeypatch.delenv('SBOM_JAVA_ARCHIVE_COMPONENTS', raising=False)
    assert Settings().java_archive_components is True
    assert Settings.from_env().java_archive_components is True
    assert Settings().java_nested_windows is False


@pytest.mark.parametrize('raw,expected', [('true', True), ('TRUE', True), ('false', False), ('FALSE', False)])
def test_archive_component_environment_can_select_explicit_legacy_rollback(monkeypatch, raw, expected):
    monkeypatch.setenv('SBOM_JAVA_ARCHIVE_COMPONENTS', raw)
    assert Settings.from_env().java_archive_components is expected


@pytest.mark.parametrize('raw', ['', '1', 'yes', 'auto', 'enabled', ' true '])
def test_archive_component_environment_rejects_ambiguous_values(monkeypatch, raw):
    monkeypatch.setenv('SBOM_JAVA_ARCHIVE_COMPONENTS', raw)
    with pytest.raises(ValueError, match='SBOM_JAVA_ARCHIVE_COMPONENTS must be true or false'):
        Settings.from_env()


@pytest.mark.parametrize('override,expected', [(None, True), ('true', True), ('false', False)])
def test_default_setting_reaches_actual_reader_and_identity_gate_without_fake_payload(
        tmp_path, monkeypatch, override, expected):
    if override is None:
        monkeypatch.delenv('SBOM_JAVA_ARCHIVE_COMPONENTS', raising=False)
    else:
        monkeypatch.setenv('SBOM_JAVA_ARCHIVE_COMPONENTS', override)
    image, peer, archive, nested = inputs(tmp_path)
    cache = tmp_path / 'cache'
    (cache / 'java-db').mkdir(parents=True)
    db = database(cache / 'java-db/trivy-java.db', sha1=hashlib.sha1(nested).digest(),
                  group='example', artifact='core', version='1')
    settings = replace(Settings.from_env(), image_archive=str(archive),
                       trivy_cache_dir=str(cache), image_temp_dir=str(tmp_path / 'scratch'))
    monkeypatch.setattr(runtime, 'peer', lambda *args: (peer, {
        'version': '0.75.0', 'database_sha256': digest(db), 'database_bytes': db.stat().st_size}))

    def forbidden_acquisition(*args):
        raise AssertionError('The existing supplied archive must be used')

    monkeypatch.setattr(runtime, 'acquire', forbidden_acquisition)
    adapted, facts = runtime.analyze(image, {}, settings)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=facts['payload_evidence'],
                            identity_envelope=facts['identity_binding_envelope'])
    assert facts['payload_evidence']['core-0']['status'] == 'unconfirmed'
    assert not facts['payload_evidence']['core-0']['path']
    assert facts['java_image_status'] == 'corroborated'
    assert {a['purl'] for a in result['selected_syft']['artifacts']} == ({PURL} if expected else set())
    assert bool(facts['identity_binding_envelope'].get('archive_presence')) is expected
    assert result['coverage']['policy_version'] == (
        'image-delivered-archive-v7' if expected else 'image-identity-payload-v4')


def _java_artifact():
    return {'id': 'unconfirmed-java', 'name': 'archive', 'version': '1.0.0', 'type': 'java-archive',
            'purl': 'pkg:maven/example/archive@1.0.0', 'foundBy': 'java-archive-cataloger',
            'locations': [{'path': '/app/archive.jar', 'accessPath': '/app/archive.jar'}],
            'licenses': [], 'language': 'java', 'cpes': []}


def test_malformed_sqlite_preserves_raw_inventory_and_publishes_partial_safe_final(
        real_catalogs, tmp_path, monkeypatch):
    source, valid_image, baseline_settings = real_catalogs
    image = copy.deepcopy(valid_image)
    image['artifacts'].append(_java_artifact())
    java = image['artifacts'][-1]
    expected_python = next(a for a in image['artifacts'] if a['name'] == 'kept-package')
    physical = {a['id']: {'status': 'unconfirmed', 'path': None} for a in image['artifacts']}
    physical[expected_python['id']] = {'status': 'confirmed', 'path': '/delivered/kept-package.py'}
    bad_db = tmp_path / 'public-java.db'
    bad_db.write_bytes(b'SQLite format 3\0' + b'\0' * 256)
    pin = digest(bad_db)

    def malformed_public_cache(*args):
        # Real failure in the new default's DB constructor, after peer success.
        # It must be caught by the scanner's optional Java boundary, not leaked.
        PublicJavaHashLookup(bad_db, pin)
        raise AssertionError('The malformed SQLite file must not be accepted')

    original_syft = scanner._syft
    monkeypatch.setattr(scanner, '_syft', lambda *args, **kwargs: copy.deepcopy(image))
    monkeypatch.setattr(scanner, '_image_identity', lambda *args: {
        'immutable_reference': 'example.com/app@sha256:' + 'a' * 64,
        'image_config_digest': 'sha256:' + 'b' * 64})
    monkeypatch.setattr(scanner, 'collect_payload', lambda *args: copy.deepcopy(physical))
    monkeypatch.setattr(runtime, 'analyze', malformed_public_cache)
    settings = replace(baseline_settings, registry_hosts=('example.com',), java_archive_components=True)
    acquired, provenance = scanner.scan_image('example.com/app@sha256:' + 'a' * 64,
                                              tmp_path / 'raw-image.json', settings)
    assert {a['id'] for a in acquired['artifacts']} == {a['id'] for a in image['artifacts']}
    assert provenance['java_image_status'] == 'UNKNOWN'
    assert provenance['java_image_error_type'] == 'DatabaseError'
    assert provenance['payload_evidence'] == physical
    assert not provenance.get('identity_binding_envelope')
    assert 'database disk image' not in json.dumps(provenance)
    # Conversion uses scanner._syft too; restore the real subprocess adapter
    # after the controlled acquisition fault instead of mocking conversion.
    monkeypatch.setattr(scanner, '_syft', original_syft)
    empty_source = copy.deepcopy(source)
    empty_source['artifacts'] = []
    empty_source['artifactRelationships'] = []
    output = tmp_path / 'partial-final'
    # Use the real pinned converter and service publisher; only unconfirmed Java
    # stays out of the final, while its original observation remains in raw.
    summary = publish_catalogs(empty_source, acquired, output, settings, core.rules_assessor,
                               {'source_kind': 'not-provided', 'image': provenance})
    assert summary['partial'] is True
    assert summary['selected_count'] == 1
    for view in ('final', 'os', 'full'):
        document = json.loads((output / (view + '.cdx.json')).read_bytes())
        validate_cyclonedx(document)
        assert not any(c.get('purl') == java['purl'] for c in document.get('components', []))
    final = json.loads((output / 'final.cdx.json').read_bytes())
    assert {c['name'] for c in final['components']} == {'kept-package'}
    raw = json.loads((output / 'image.syft.json').read_bytes())
    assert any(a['id'] == java['id'] for a in raw['artifacts'])


def test_plain_npm_does_not_require_java_tools_or_database_with_default_enabled(tmp_path, monkeypatch):
    from test_npm_type_presence import image as type_image

    image = type_image({'types': 'index.d.ts'})
    monkeypatch.setattr(scanner, '_syft', lambda *args, **kwargs: copy.deepcopy(image))
    monkeypatch.setattr(scanner, '_image_identity', lambda *args: {
        'immutable_reference': 'example.com/app@sha256:' + 'a' * 64})

    def forbidden_java(*args):
        raise AssertionError('A pure Node image must not invoke Trivy or open Java DB')

    monkeypatch.setattr(runtime, 'analyze', forbidden_java)
    settings = Settings(registry_hosts=('example.com',))
    assert settings.java_archive_components is True
    acquired, provenance = scanner.scan_image('example.com/app@sha256:' + 'a' * 64,
                                              tmp_path / 'image.json', settings)
    assert 'java_image_status' not in provenance
    assert provenance['payload_evidence']['types']['payload_kind'] == 'declared_type_surface'
    assert core.reconcile({'artifacts': []}, acquired,
                          payload_evidence=provenance['payload_evidence'])['coverage']['selected_artifacts'] == 1

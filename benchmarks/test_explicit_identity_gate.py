import copy
from unittest.mock import patch

import pytest
from explicit_identity_gate import candidates, prepare
from test_trivy_payload_bridge import inputs
from trivy_payload_bridge import bridge

from sbom_creator import core


def fixture(mutate=None):
    image, peer, physical = inputs()
    if mutate:
        mutate(image, peer, physical)
    adapted, _, audit = bridge(image, peer, physical)
    payload, envelope = prepare(adapted, {'existing_bridge': audit, 'supplemental': []})
    return adapted, payload, envelope, physical


def reconcile(image, payload, envelope):
    def build(source, image, payload):
        return candidates(source, image, payload, envelope)
    with patch.object(core, 'build_candidates', build):
        return core.reconcile({'artifacts': []}, image, payload_evidence=payload)


def test_valid_identity_and_actual_payload_include():
    image, payload, envelope, physical = fixture()
    assert payload == physical
    assert reconcile(image, payload, envelope)['decisions'][0]['decision'] == 'INCLUDE'


def test_failed_identity_keeps_physical_truth_and_is_unknown():
    image, payload, envelope, physical = fixture(lambda i, p, w: p['components'].clear())
    assert payload == physical
    row = reconcile(image, payload, envelope)['decisions'][0]
    assert row['decision'] == 'UNKNOWN'
    fact = row['evidence'][0]
    assert fact['payload']['status'] == 'confirmed'
    assert fact['identity_binding']['status'] == 'UNKNOWN'
    assert fact['presence_kind'] == 'metadata_without_confirmed_identity'
    assert row['review_reason'] != 'PAYLOAD_NOT_CONFIRMED'


@pytest.mark.parametrize('field', ['purl', 'name', 'version', 'locations', 'foundBy'])
def test_stale_catalog_cannot_reuse_binding(field):
    image, payload, envelope, _ = fixture()
    image['artifacts'][0][field] = 'changed'
    with pytest.raises(ValueError, match='mismatch'):
        candidates({'artifacts': []}, image, payload, envelope)


def test_stale_payload_cannot_reuse_binding():
    image, payload, envelope, _ = fixture()
    payload['a']['path'] = '/other:A.class'
    with pytest.raises(ValueError, match='mismatch'):
        candidates({'artifacts': []}, image, payload, envelope)


def test_missing_binding_does_not_promote_payload():
    image, payload, envelope, _ = fixture()
    envelope['artifacts'].clear()
    assert reconcile(image, payload, envelope)['decisions'][0]['decision'] == 'UNKNOWN'


def test_duplicate_audit_fails_closed_without_mutating_inputs():
    image, peer, physical = inputs()
    adapted, _, audit = bridge(image, peer, physical)
    audit['packages'].append(copy.deepcopy(audit['packages'][0]))
    previous = copy.deepcopy((adapted, audit))
    payload, envelope = prepare(adapted, {'existing_bridge': audit, 'supplemental': []})
    assert envelope['artifacts']['a']['status'] == 'UNKNOWN'
    assert reconcile(adapted, payload, envelope)['decisions'][0]['decision'] == 'UNKNOWN'
    assert (adapted, audit) == previous


def test_identity_confirmation_cannot_replace_missing_payload():
    image, payload, envelope, _ = fixture(lambda i, p, w: w['a'].update(status='unconfirmed'))
    # Even a trusted identity confirmation cannot turn an absent payload into bytes.
    envelope['artifacts']['a']['status'] = 'BOUND'
    row = reconcile(image, payload, envelope)['decisions'][0]
    assert row['decision'] == 'UNKNOWN'
    assert row['review_reason'] == 'PAYLOAD_NOT_CONFIRMED'


def test_non_java_observations_unchanged():
    image, payload, envelope, _ = fixture()
    image['artifacts'].append({'id': 'npm', 'foundBy': 'javascript-package-cataloger',
                              'type': 'npm', 'purl': 'pkg:npm/demo@1.0.0',
                              'name': 'demo', 'version': '1.0.0'})
    envelope['catalog_sha256'] = core.checksum(image)
    expected = core.build_candidates({'artifacts': []}, image, payload)
    actual = candidates({'artifacts': []}, image, payload, envelope)
    assert next(c for c in actual if c['image_artifact_ids'] == ['npm']) == next(
        c for c in expected if c['image_artifact_ids'] == ['npm'])


@pytest.mark.parametrize('mutate', [
    lambda image, audit: image['artifacts'][0]['locations'][0].update(layerID='sha256:' + 'd'*64),
    lambda image, audit: audit['existing_bridge']['packages'][0].update(identity='pkg:maven/other/a@2'),
    lambda image, audit: audit['existing_bridge']['packages'][0].update(path_layer=['/other.jar', 'bad']),
])
def test_claimed_bound_with_wrong_identity_path_or_layer_is_unknown(mutate):
    image, peer, physical = inputs()
    image, _, audit = bridge(image, peer, physical)
    audit = {'existing_bridge': audit, 'supplemental': []}
    mutate(image, audit)
    payload, envelope = prepare(image, audit)
    assert payload == physical
    assert reconcile(image, payload, envelope)['decisions'][0]['decision'] == 'UNKNOWN'


def test_one_bound_instance_cannot_promote_unbound_same_purl_sibling():
    image, payload, envelope, _ = fixture()
    sibling = copy.deepcopy(image['artifacts'][0])
    sibling['id'] = 'sibling'
    image['artifacts'].append(sibling)
    payload['sibling'] = copy.deepcopy(payload['a'])
    envelope.update(catalog_sha256=core.checksum(image), payload_sha256=core.checksum(payload))
    row = reconcile(image, payload, envelope)['decisions'][0]
    assert row['decision'] == 'INCLUDE'
    assert row['selected_image_artifact_ids'] == ['a']


@pytest.mark.parametrize('config', [None, '', 'not-a-digest'])
def test_missing_or_invalid_config_cannot_create_envelope(config):
    image, peer, physical = inputs()
    image, _, audit = bridge(image, peer, physical)
    image['source']['metadata']['imageID'] = config
    audit['image_config_digest'] = config
    with pytest.raises(ValueError, match='another image'):
        prepare(image, {'existing_bridge': audit, 'supplemental': []})


def test_supplemental_audit_cannot_relabel_syft_producer():
    image, peer, physical = inputs()
    image, _, audit = bridge(image, peer, physical)
    row = audit['packages'][0]
    fake = {'artifact_id': 'a', 'status': 'CORROBORATED_TRIVY_ONLY',
            'identity': row['identity'], 'path': row['path_layer'][0],
            'layer': row['path_layer'][1], 'observed_payload': physical['a']}
    audit['packages'] = []
    payload, envelope = prepare(image, {'existing_bridge': audit, 'supplemental': [fake]})
    assert payload == physical
    assert reconcile(image, payload, envelope)['decisions'][0]['decision'] == 'UNKNOWN'

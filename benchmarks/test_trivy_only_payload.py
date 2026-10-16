import copy
import hashlib
import io
import json
import tarfile
from unittest.mock import patch

import pytest
from test_bounded_jar_evidence import jar
from trivy_only_payload import CATALOGER, supplement, virtual_archive

from sbom_creator import core


def fixture(tmp_path, contents):
    raw = jar([('lib/resources.jar', jar(contents))])
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w') as archive:
        member = tarfile.TarInfo('app.jar')
        member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))
    layer = layer.getvalue()
    layer_id = 'sha256:' + hashlib.sha256(layer).hexdigest()
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'diff_ids': [layer_id]}}).encode()
    config_id = 'sha256:' + hashlib.sha256(config).hexdigest()
    output = tmp_path / 'image.tar'
    with tarfile.open(output, 'w') as archive:
        for name, data in [('manifest.json', json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode()),
                           ('config.json', config), ('layer.tar', layer)]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    image = {'source': {'metadata': {'imageID': config_id}}, 'artifacts': [], 'artifactRelationships': [],
             'files': [{'id': 'f1', 'location': {'path': '/app.jar', 'layerID': layer_id},
                        'metadata': {'type': 'RegularFile', 'size': len(raw)}}]}
    peer = {'metadata': {'component': {'properties': [{'name': 'aquasecurity:trivy:ImageID', 'value': config_id}]}},
            'components': [{'name': 'resources', 'group': 'example', 'version': '1',
                            'purl': 'pkg:maven/example/resources@1', 'bom-ref': 'peer1', 'properties': [
                                {'name': 'aquasecurity:trivy:FilePath', 'value': 'app.jar/lib/resources.jar'},
                                {'name': 'aquasecurity:trivy:LayerDiffID', 'value': layer_id}]}]}
    return image, peer, output


def test_explicit_trivy_producer_requires_real_resource_bytes(tmp_path):
    image, peer, archive = fixture(tmp_path, [('META-INF/resources/style.css', b'a{}')])
    result, witnesses, audit = supplement(image, peer, {}, archive)
    assert not image['artifacts']
    assert len(result['artifacts']) == 1
    artifact = result['artifacts'][0]
    assert artifact['foundBy'] == CATALOGER != 'java-archive-cataloger'
    assert artifact['purl'] == 'pkg:maven/example/resources@1'
    assert witnesses[artifact['id']]['status'] == 'confirmed'
    assert audit['supplemental'][0]['original_syft_artifact'] is None
    assert audit['resource_counters']['resource_witnesses'] == 1


@pytest.mark.parametrize('contents', [[('META-INF/MANIFEST.MF', b'Manifest-Version: 1')],
                                     [('pom.xml', b'<project/>')], [('fake.class', b'no-magic')]])
def test_metadata_or_false_class_never_added(tmp_path, contents):
    image, peer, archive = fixture(tmp_path, contents)
    result, _, audit = supplement(image, peer, {}, archive)
    assert not result['artifacts']
    assert audit['supplemental'][0]['status'] == 'UNKNOWN'


def test_wrong_final_layer_is_unknown_without_payload_read(tmp_path):
    image, peer, archive = fixture(tmp_path, [('style.css', b'a{}')])
    peer['components'][0]['properties'][1]['value'] = 'sha256:' + 'f' * 64
    result, _, audit = supplement(image, peer, {}, archive)
    assert not result['artifacts']
    assert audit['resource_counters'] is None


def test_physical_archive_config_must_match_catalogs(tmp_path):
    image, peer, archive = fixture(tmp_path, [('style.css', b'a{}')])
    image['source']['metadata']['imageID'] = 'sha256:' + 'f' * 64
    peer['metadata']['component']['properties'][0]['value'] = image['source']['metadata']['imageID']
    with pytest.raises(ValueError, match='Physical archive config'):
        supplement(image, peer, {}, archive)


def test_duplicate_peer_identity_not_added(tmp_path):
    image, peer, archive = fixture(tmp_path, [('style.css', b'a{}')])
    peer['components'].append(copy.deepcopy(peer['components'][0]))
    result, _, audit = supplement(image, peer, {}, archive)
    assert not result['artifacts']
    assert audit['supplemental'][0]['status'] == 'UNKNOWN'


def test_does_not_bypass_existing_syft_unknown(tmp_path):
    image, peer, archive = fixture(tmp_path, [('style.css', b'a{}')])
    image['artifacts'] = [{'id': 'original', 'foundBy': 'java-archive-cataloger',
                           'metadata': {'virtualPath': '/app.jar:lib/resources.jar'},
                           'locations': [{'path': '/app.jar', 'layerID': image['files'][0]['location']['layerID']}]}]
    result, _, audit = supplement(image, peer, {}, archive)
    assert len(result['artifacts']) == 1
    assert result['artifacts'][0]['id'] == 'original'
    assert not audit['supplemental']


def test_explicit_trust_and_payload_both_required_by_reconciler(tmp_path):
    image, peer, archive = fixture(tmp_path, [('style.css', b'a{}')])
    result, evidence, _ = supplement(image, peer, {}, archive)
    source = {'artifacts': [], 'artifactRelationships': [], 'files': [], 'source': {}}
    assert core.reconcile(source, result, core.rules_assessor, evidence)['decisions'][0]['decision'] == 'UNKNOWN'
    with patch.dict(core._DIRECT_CATALOGERS, {CATALOGER: 'archive_metadata'}), patch.object(
            core, 'PAYLOAD_CATALOGERS', core.PAYLOAD_CATALOGERS | {CATALOGER}):
        assert core.reconcile(source, result, core.rules_assessor, evidence)['decisions'][0]['decision'] == 'INCLUDE'
        assert core.reconcile(source, result, core.rules_assessor, {})['decisions'][0]['decision'] == 'UNKNOWN'


@pytest.mark.parametrize('target', ['/elsewhere.jar/lib/a.jar', '/app.jar/lib/pom.xml',
                                   '/app.jar/' + '/'.join('a.jar' for _ in range(9))])
def test_only_supported_archive_chain_can_be_probed(target):
    with pytest.raises(ValueError):
        virtual_archive(target, '/app.jar')

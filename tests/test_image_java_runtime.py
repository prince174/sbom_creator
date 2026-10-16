import gzip
import hashlib
import io
import json
import stat
import tarfile
import zipfile

import pytest

from sbom_creator import core
from sbom_creator.acquire import Settings
from sbom_creator.image_java.runtime import acquire, corroborate


def jar(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        for path, raw in entries:
            archive.writestr(path, raw)
    return out.getvalue()


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for path, raw in entries:
            member = tarfile.TarInfo(path)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return out.getvalue()


def fixture(tmp_path, *, wrong_layer=False, metadata_only=False, core_entries=None, core_raw=None):
    nested = jar([('pom.xml', b'<project/>')]) if metadata_only else jar([('X.class', b'\xca\xfe\xba\xbe')])
    if core_entries is not None:
        nested = jar(core_entries)
    if core_raw is not None:
        nested = core_raw
    outer = jar([('lib/core.jar', nested), ('lib/resources.jar', jar([('META-INF/resources/style.css', b'a{}')]))])
    layer = tar([('app.jar', outer)])
    digest = 'sha256:'+hashlib.sha256(layer).hexdigest()
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'diff_ids': [digest]}}).encode()
    config_id = 'sha256:'+hashlib.sha256(config).hexdigest()
    image_path = tmp_path/'image.tar'
    image_path.write_bytes(tar([('manifest.json', json.dumps([{'Config': 'config.json', 'Layers': ['layer.gz']}]).encode()),
                               ('config.json', config), ('layer.gz', gzip.compress(layer))]))
    image = {'source': {'metadata': {'imageID': config_id}}, 'artifacts': [
        {'id': 'a', 'name': 'core', 'version': '1', 'type': 'java-archive',
         'foundBy': 'java-archive-cataloger', 'purl': 'pkg:maven/incorrect/core@1',
         'metadata': {'virtualPath': '/app.jar:lib/core.jar'},
         'locations': [{'path': '/app.jar', 'layerID': digest, 'accessPath': '/app.jar:lib/core.jar'}]}],
        'files': [{'location': {'path': '/app.jar', 'layerID': digest},
                   'metadata': {'size': len(outer), 'type': 'RegularFile'}}]}
    peer = {'metadata': {'component': {'properties': [{'name': 'aquasecurity:trivy:ImageID', 'value': config_id}]}},
            'components': []}
    for name in ('core', 'resources'):
        peer['components'].append({'name': name, 'group': 'example', 'version': '2',
            'purl': 'pkg:maven/example/'+name+'@2', 'bom-ref': name, 'properties': [
                {'name': 'aquasecurity:trivy:FilePath', 'value': 'app.jar/lib/'+name+'.jar'},
                {'name': 'aquasecurity:trivy:LayerDiffID', 'value': 'sha256:'+'0'*64 if wrong_layer else digest}]})
    return image, peer, image_path


def test_runtime_image_only_identity_and_resource_corroboration(tmp_path):
    image, peer, archive = fixture(tmp_path)
    adapted, physical, envelope, audit = corroborate(image, archive, peer, temporary=tmp_path)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert {a['purl'] for a in result['selected_syft']['artifacts']} == {
        'pkg:maven/example/core@2', 'pkg:maven/example/resources@2'}
    assert audit['layer_resources']['normalizations'] == 1  # shared primary/supplement budget
    assert image['artifacts'][0]['purl'] == 'pkg:maven/incorrect/core@1'
    assert result['coverage']['policy_version'] == 'image-identity-payload-v4'
    assert 'source' not in envelope


def test_unregistered_producer_is_unknown_without_identity_envelope(tmp_path):
    image, peer, archive = fixture(tmp_path)
    adapted, physical, _, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical)
    assert 'pkg:maven/example/resources@2' not in {a['purl'] for a in result['selected_syft']['artifacts']}


def test_wrong_layer_keeps_physical_truth_but_cannot_include_identity(tmp_path):
    image, peer, archive = fixture(tmp_path, wrong_layer=True)
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    assert physical['a']['status'] == 'confirmed'
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert not result['selected_syft']['artifacts']
    assert result['decisions'][0]['evidence'][0]['identity_binding']['status'] == 'UNKNOWN'


def test_metadata_only_is_not_fabricated_class_payload(tmp_path):
    image, peer, archive = fixture(tmp_path, metadata_only=True)
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert 'pkg:maven/example/core@2' not in {a['purl'] for a in result['selected_syft']['artifacts']}


def test_stale_envelope_rejected(tmp_path):
    image, peer, archive = fixture(tmp_path)
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    adapted['artifacts'][0]['version'] = 'unexpected'
    with pytest.raises(ValueError, match='mismatch'):
        core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)


@pytest.mark.parametrize('version', ['0.22.1', '8a72a424fdecb4caa14f2d525e5d2503331442b5'])
def test_registry_pull_uses_only_immutable_reference_and_isolated_credentials(tmp_path, monkeypatch, version):
    monkeypatch.setenv('SBOM_REGISTRY_USERNAME', 'synthetic')
    monkeypatch.setenv('SBOM_REGISTRY_PASSWORD', 'synthetic-secret')
    monkeypatch.setenv('SBOM_API_TOKEN', 'api-secret')
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        assert 'SBOM_API_TOKEN' not in kwargs['env']
        if args[1] == 'version':
            return version
        assert '--insecure' not in args
        assert args[2] == 'example.com/app@sha256:'+'a'*64
        assert 'synthetic-secret' not in ' '.join(args)
        return ''
    monkeypatch.setattr('sbom_creator.image_java.runtime.run_command', run)
    acquire('example.com/app@sha256:'+'a'*64, tmp_path/'image.tar', Settings(), tmp_path)
    assert len(calls) == 2


@pytest.mark.parametrize('path', ['../escape.class', '/absolute.class'])
def test_runtime_unsafe_nested_zip_cannot_confirm_java_payload(tmp_path, path):
    image, peer, archive = fixture(tmp_path, core_entries=[(path, b'\xca\xfe\xba\xbe')])
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert 'pkg:maven/example/core@2' not in {a['purl'] for a in result['selected_syft']['artifacts']}
    assert physical['a']['status'] != 'confirmed'


def test_runtime_duplicate_zip_member_cannot_hide_conflicting_class_payload(tmp_path):
    with pytest.warns(UserWarning, match='Duplicate name'):
        image, peer, archive = fixture(tmp_path, core_entries=[('X.class', b'bad!'), ('X.class', b'\xca\xfe\xba\xbe')])
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert 'pkg:maven/example/core@2' not in {a['purl'] for a in result['selected_syft']['artifacts']}


def test_runtime_zip_symlink_is_never_treated_as_class_bytes(tmp_path):
    link = zipfile.ZipInfo('Linked.class')
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    image, peer, archive = fixture(tmp_path, core_entries=[(link, b'\xca\xfe\xba\xbe')])
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert 'pkg:maven/example/core@2' not in {a['purl'] for a in result['selected_syft']['artifacts']}


def test_runtime_outer_tar_extensions_are_checked_before_tarfile_allocation(tmp_path, monkeypatch):
    from sbom_creator.image_java.seekable_jar_evidence import JarFiles
    outer = tmp_path/'oversized-extension.tar'
    member = tarfile.TarInfo('PaxHeaders/hostile')
    member.type = tarfile.XHDTYPE
    member.size = 65_537  # beyond bounded metadata before parser allocation
    outer.write_bytes(member.tobuf() + bytes(((member.size+511)//512)*512) + bytes(1024))
    original = tarfile.open
    def refuse_unpreflighted(*args, **kwargs):
        pytest.fail('tarfile parser allocated before outer metadata preflight')
    monkeypatch.setattr(tarfile, 'open', refuse_unpreflighted)
    with pytest.raises(ValueError, match='extension budget'):
        JarFiles(outer, {'source': {'metadata': {'imageID': 'sha256:'+'a'*64}}, 'files': []})
    monkeypatch.setattr(tarfile, 'open', original)


def test_runtime_rejects_literal_zip_backslashes_before_windows_normalization(tmp_path):
    # On Windows ZipInfo normalizes names while writing, so edit both actual
    # local and central headers to present a genuinely hostile archive.
    raw = jar([('bad/escape.class', b'\xca\xfe\xba\xbe')])
    hostile = raw.replace(b'bad/escape.class', b'bad\\escape.class')
    assert hostile.count(b'bad\\escape.class') == 2
    image, peer, archive = fixture(tmp_path, core_raw=hostile)
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert 'pkg:maven/example/core@2' not in {a['purl'] for a in result['selected_syft']['artifacts']}
    assert physical['a']['status'] != 'confirmed'


def test_runtime_catalog_config_cannot_bind_another_physical_image(tmp_path):
    image, peer, archive = fixture(tmp_path)
    image['source']['metadata']['imageID'] = 'sha256:'+'f'*64
    with pytest.raises(ValueError, match='Physical config differs'):
        corroborate(image, archive, peer)


def test_runtime_duplicate_final_file_paths_are_ambiguous(tmp_path):
    image, peer, archive = fixture(tmp_path)
    image['files'].append(dict(image['files'][0]))
    with pytest.raises(ValueError, match='Ambiguous final filesystem path'):
        corroborate(image, archive, peer)


def test_runtime_rejected_layer_is_not_decompressed_again(tmp_path, monkeypatch):
    from sbom_creator.image_java import seekable_layer_index
    from sbom_creator.image_java.seekable_jar_evidence import JarFiles
    image, _, archive = fixture(tmp_path)
    files = JarFiles(archive, image, temporary=tmp_path)
    calls = []
    original = gzip.GzipFile
    def observe(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(seekable_layer_index.gzip, 'GzipFile', observe)
    monkeypatch.setattr(seekable_layer_index, 'MAX_DISK', 1)
    try:
        for _ in range(20):
            with pytest.raises(ValueError, match='normalization budget|Previously rejected layer'):
                files.witness(image['artifacts'][0])
        assert len(calls) == 1
        assert files.layers_reader.stats['payload_read_bytes'] == 0
        assert files.stats['class_witnesses'] == 0
    finally:
        files.close()


def test_runtime_closed_file_window_cannot_reuse_cached_payload(tmp_path):
    from sbom_creator.image_java.seekable_jar_evidence import JarFiles
    image, _, archive = fixture(tmp_path)
    files = JarFiles(archive, image, temporary=tmp_path)
    view = files.source('/app.jar')
    initial = view.read(4)
    assert initial
    view.seek(0)
    files.close()
    with pytest.raises(ValueError, match='Closed cached view'):
        view.read(4)


def test_runtime_trivy_only_resource_inventory_does_not_require_syft_java_artifact(tmp_path):
    image, peer, archive = fixture(tmp_path)
    image['artifacts'] = []
    peer['components'] = [c for c in peer['components'] if c['name'] == 'resources']
    adapted, physical, envelope, _ = corroborate(image, archive, peer)
    result = core.reconcile({'artifacts': []}, adapted, payload_evidence=physical, identity_envelope=envelope)
    assert [a['purl'] for a in result['selected_syft']['artifacts']] == ['pkg:maven/example/resources@2']
    assert result['selected_syft']['artifacts'][0]['foundBy'] == 'trivy-java-archive-cataloger'
    assert all(e['status'] == 'confirmed' for e in physical.values())


@pytest.mark.parametrize('version', ['0.22.2', '8a72a424fdecb4caa14f2d525e5d2503331442b4', 'development'])
def test_registry_pull_rejects_unpinned_crane_commit_or_version(tmp_path, monkeypatch, version):
    monkeypatch.setattr('sbom_creator.image_java.runtime.secret', lambda *a: '')
    def run(args, **kwargs):
        assert args[1] == 'version', 'Unpinned crane must never acquire an image'
        return version
    monkeypatch.setattr('sbom_creator.image_java.runtime.run_command', run)
    with pytest.raises(ValueError, match='Pinned crane version required'):
        acquire('example.com/app@sha256:'+'a'*64, tmp_path/'image.tar', Settings(), tmp_path)


def test_scanner_archive_file_hint_runs_java_analysis_without_syft_java_package(tmp_path, monkeypatch):
    from sbom_creator import scanner
    image = {'artifacts': [], 'files': [{'location': {'path': '/app/resources.jar'},
              'metadata': {'type': 'RegularFile', 'size': 10}}]}
    monkeypatch.setattr(scanner, '_syft', lambda *a, **kw: image)
    monkeypatch.setattr(scanner, '_image_identity', lambda *a: {'immutable_reference': 'example.com/app@sha256:'+'a'*64})
    monkeypatch.setattr(scanner, 'collect_payload', lambda *a: {})
    calls = []
    def corroborate(data, provenance, settings):
        calls.append(data)
        return data, {'java_image_status': 'corroborated'}
    monkeypatch.setattr('sbom_creator.image_java.runtime.analyze', corroborate)
    _, provenance = scanner.scan_image('example.com/app@sha256:'+'a'*64, tmp_path/'image.json',
        Settings(registry_hosts=('example.com',)))
    assert calls == [image] and provenance['java_image_status'] == 'corroborated'


def test_optional_java_peer_schema_failure_preserves_image_inventory(tmp_path, monkeypatch):
    from jsonschema.exceptions import ValidationError

    from sbom_creator import scanner
    image = {'artifacts': [{'id': 'node', 'foundBy': 'javascript-package-cataloger'}],
             'files': [{'location': {'path': '/app/resource.jar'}, 'metadata': {'type': 'RegularFile'}}]}
    physical = {'node': {'status': 'confirmed', 'path': '/app/index.js'}}
    monkeypatch.setattr(scanner, '_syft', lambda *a, **kw: image)
    monkeypatch.setattr(scanner, '_image_identity', lambda *a: {'immutable_reference': 'example.com/app@sha256:'+'a'*64})
    monkeypatch.setattr(scanner, 'collect_payload', lambda *a: physical)
    def invalid(*args):
        raise ValidationError('Untrusted scanner content must not enter public errors')
    monkeypatch.setattr('sbom_creator.image_java.runtime.analyze', invalid)
    actual, provenance = scanner.scan_image('example.com/app@sha256:'+'a'*64, tmp_path/'image.json',
        Settings(registry_hosts=('example.com',)))
    assert actual == image and provenance['payload_evidence'] == physical
    assert provenance['java_image_status'] == 'UNKNOWN'
    assert provenance['java_image_error_type'] == 'ValidationError'
    assert 'Untrusted' not in json.dumps(provenance)

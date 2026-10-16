"""Declared npm type files are delivery evidence, never executable-code proof."""
import base64
import copy
import json
import posixpath

import pytest
from test_core import doc, package
from test_payload import archive_fixture

from sbom_creator.core import reconcile
from sbom_creator.payload import collect

BASE = '/app/node_modules/@example/token'
DECLARATION = b'export interface Token { readonly length: number; }\n'


def npm(pid='types', root=BASE):
    return package(pid, '@example/token', '1.2.3', type='npm',
                   purl='pkg:npm/%40example/token@1.2.3',
                   foundBy='javascript-package-cataloger',
                   locations=[{'path': root + '/package.json', 'layerID': 'sha256:fixture'}])


def file_entry(name, data, *, kind='RegularFile', inline=True):
    result = {'id': name, 'location': {'path': name, 'layerID': 'sha256:fixture'},
              'metadata': {'type': kind, 'size': len(data)}}
    if inline:
        result['contents'] = base64.b64encode(data).decode()
    return result


def image(fields=None, files=None, *, artifacts=None):
    manifest = {'name': '@example/token', 'version': '1.2.3', 'main': '', **(fields or {})}
    return doc(*(artifacts if artifacts is not None else [npm()]), files=[
        file_entry(BASE + '/package.json', json.dumps(manifest).encode()),
        *(files if files is not None else [file_entry(BASE + '/index.d.ts', DECLARATION, inline=False)])])


@pytest.mark.parametrize('fields', [
    {'types': 'index.d.ts'}, {'typings': 'index.d.ts'},
    {'types': './index.d.ts'}, {'types': 'index.d.ts', 'typings': 'index.d.ts'},
])
def test_declared_final_type_file_is_labelled_separately_and_included(fields):
    document = image(fields)
    evidence = collect(document)
    assert evidence['types']['status'] == 'confirmed'
    assert evidence['types']['path'] == BASE + '/index.d.ts'
    assert evidence['types']['payload_kind'] == 'declared_type_surface'
    result = reconcile(doc(), document, payload_evidence=evidence)
    assert result['selected_syft']['artifacts'] == document['artifacts']
    assert result['coverage']['runtime_usage'] == 'not_measured'
    assert result['decisions'][0]['evidence'][0]['payload']['payload_kind'] == 'declared_type_surface'
    assert result['coverage']['policy_version'] == 'image-evidence-and-payload-v4'


def test_nested_owned_declared_type_path_without_manifest_child_is_supported():
    document = image({'types': './dist/types/index.d.ts'}, files=[
        file_entry(BASE + '/dist/types/index.d.ts', DECLARATION, inline=False)])
    assert collect(document)['types']['path'] == BASE + '/dist/types/index.d.ts'


@pytest.mark.parametrize('field', ['types', 'typings'])
@pytest.mark.parametrize('unsafe', [
    '', '../other/index.d.ts', 'safe/../index.d.ts', '/app/other/index.d.ts',
    r'dist\index.d.ts', 'https://example.invalid/index.d.ts', 'C:/types/index.d.ts',
    'index.d.ts?download=1', 'index.d.ts#types', 'index.js', None, False, ['index.d.ts'],
])
def test_type_declarations_reject_unsafe_or_nonconcrete_fields(field, unsafe):
    files = [file_entry(BASE + '/index.d.ts', DECLARATION)]
    if isinstance(unsafe, str) and unsafe.endswith('.d.ts'):
        target = posixpath.normpath(posixpath.join(BASE, unsafe))
        if target != BASE + '/index.d.ts':
            files.append(file_entry(target, DECLARATION))
    document = image({field: unsafe}, files=files)
    evidence = collect(document)
    assert evidence['types']['status'] == 'unconfirmed'
    assert reconcile(doc(), document, payload_evidence=evidence)['decisions'][0]['decision'] == 'UNKNOWN'


@pytest.mark.parametrize('fields', [
    {}, {'typesVersions': {'*': {'*': ['index.d.ts']}}},
    {'exports': {'.': {'types': './index.d.ts'}}},
    {'files': ['index.d.ts']},
])
def test_no_arbitrary_type_file_or_unsupported_export_inference(fields):
    evidence = collect(image(fields))
    assert evidence['types']['status'] == 'unconfirmed'


@pytest.mark.parametrize('files', [
    [], [file_entry(BASE + '/README.md', b'types are described here')],
    [file_entry(BASE + '/index.d.ts', b'')],
    [file_entry(BASE + '/index.d.ts', DECLARATION, kind='SymbolicLink')],
    [file_entry(BASE + '/index.d.ts', DECLARATION, kind='Directory')],
])
def test_missing_empty_nonregular_or_manifest_only_cannot_supply_type_evidence(files):
    evidence = collect(image({'types': 'index.d.ts'}, files=files))
    assert evidence['types']['status'] == 'unconfirmed'


@pytest.mark.parametrize('other', ['other.d.ts', '../other.d.ts', None, False])
def test_conflicting_types_and_typings_remain_unknown(other):
    document = image({'types': 'index.d.ts', 'typings': other}, files=[
        file_entry(BASE + '/index.d.ts', DECLARATION), file_entry(BASE + '/other.d.ts', DECLARATION)])
    assert collect(document)['types']['status'] == 'unconfirmed'


@pytest.mark.parametrize('root', [BASE + '/child', BASE + '/node_modules/child'])
def test_declared_type_cannot_borrow_another_package_file(root):
    relative = root.removeprefix(BASE + '/') + '/index.d.ts'
    document = image({'types': relative}, files=[
        file_entry(root + '/package.json', b'{}'), file_entry(root + '/index.d.ts', DECLARATION)],
        artifacts=[npm(), npm('child', root)])
    assert collect(document)['types']['status'] == 'unconfirmed'


def test_nested_node_modules_is_rejected_even_if_child_catalog_entry_is_missing():
    document = image({'types': 'node_modules/child/index.d.ts'}, files=[
        file_entry(BASE + '/node_modules/child/index.d.ts', DECLARATION)])
    assert collect(document)['types']['status'] == 'unconfirmed'


def test_same_purl_sibling_without_own_declared_file_does_not_get_promoted():
    sibling = '/app/other/node_modules/@example/token'
    document = image({'types': 'index.d.ts'}, artifacts=[npm(), npm('sibling', sibling)])
    document['files'].append(file_entry(sibling + '/package.json', b'{"types":"index.d.ts","main":""}'))
    evidence = collect(document)
    assert evidence['types']['status'] == 'confirmed'
    assert evidence['sibling']['status'] == 'unconfirmed'
    result = reconcile(doc(), document, payload_evidence=evidence)
    assert [artifact['id'] for artifact in result['selected_syft']['artifacts']] == ['types']


@pytest.mark.parametrize('fields,filename,data', [
    ({'main': 'index.js', 'types': 'index.d.ts'}, 'index.js', b'module.exports=1'),
    ({'main': 'index.json', 'types': 'index.d.ts'}, 'index.json', b'{"value":1}'),
    ({'main': '', 'types': 'index.d.ts'}, 'other.mjs', b'export const value=1'),
])
def test_existing_js_and_data_payload_has_priority_and_does_not_become_type_claim(fields, filename, data):
    document = image(fields, files=[file_entry(BASE + '/' + filename, data),
                                  file_entry(BASE + '/index.d.ts', DECLARATION)])
    evidence = collect(document)['types']
    assert evidence['path'] == BASE + '/' + filename
    assert evidence.get('payload_kind') != 'declared_type_surface'


def test_invalid_type_field_does_not_remove_existing_javascript_payload():
    document = image({'main': 'index.js', 'types': '../outside.d.ts'}, files=[
        file_entry(BASE + '/index.js', b'export default 1')])
    assert collect(document)['types']['path'] == BASE + '/index.js'


def test_no_source_artifact_can_borrow_image_type_confirmation():
    document = image({'types': 'index.d.ts'})
    source = doc(npm('source'))
    evidence = collect(document)
    result = reconcile(source, document, payload_evidence=evidence)
    assert result['selected_syft']['artifacts'] == document['artifacts']
    assert result['decisions'][0]['source_artifact_ids'] == ['source']
    assert result['decisions'][0]['selected_image_artifact_ids'] == ['types']


def test_layer_and_inline_modes_observe_the_same_declared_final_file(tmp_path):
    artifact = npm()
    data = {BASE + '/package.json': b'{"name":"@example/token","version":"1.2.3","main":"","types":"index.d.ts"}',
            BASE + '/index.d.ts': DECLARATION}
    document, archive = archive_fixture(tmp_path, data, [artifact])
    disk = collect(document, archive)
    inline = copy.deepcopy(document)
    for entry in inline['files']:
        entry['contents'] = base64.b64encode(data[entry['location']['path']]).decode()
    embedded = collect(inline)
    for observed in (disk['types'], embedded['types']):
        assert observed['status'] == 'confirmed'
        assert observed['path'] == BASE + '/index.d.ts'
        assert observed['payload_kind'] == 'declared_type_surface'


def test_stale_lower_layer_type_file_not_in_final_inventory_does_not_confirm(tmp_path):
    data = {BASE + '/package.json': b'{"name":"@example/token","version":"1.2.3","main":"","types":"index.d.ts"}',
            BASE + '/index.d.ts': DECLARATION}
    document, archive = archive_fixture(tmp_path, data, [npm()], missing=[BASE + '/index.d.ts'])
    assert collect(document, archive)['types']['status'] == 'unconfirmed'


@pytest.mark.parametrize('fields', [
    {'name': '@example/other'}, {'version': '1.2.4'}, {'version': '^1.2.3'},
    {'name': None}, {'version': None}, {'name': ''}, {'version': ''},
])
def test_declared_types_require_actual_manifest_identity_matching_catalog(fields):
    assert collect(image({'types': 'index.d.ts', **fields}))['types']['status'] == 'unconfirmed'


@pytest.mark.parametrize('raw', [
    b'{', b'[]', b'null',
    b'{"name":"@example/token","version":"1.2.3","main":"","types":"index.d.ts","types":"other.d.ts"}',
    b'{"name":"@example/token","version":"1.2.3","main":"","types":"other.d.ts","types":"index.d.ts"}',
    b'{"name":"@example/other","name":"@example/token","version":"1.2.3","main":"","types":"index.d.ts"}',
    b'{"name":"@example/token","version":"1.2.4","version":"1.2.3","main":"","types":"index.d.ts"}',
])
def test_ambiguous_or_malformed_manifest_never_confirms_type_delivery(raw):
    document = image({'types': 'index.d.ts'})
    document['files'][0] = file_entry(BASE + '/package.json', raw)
    assert collect(document)['types']['status'] == 'unconfirmed'


@pytest.mark.parametrize('kind', ['SymbolicLink', 'HardLink', 'RegularFile'])
def test_declared_type_cannot_walk_through_non_directory_final_ancestor(kind):
    document = image({'types': 'linked/index.d.ts'}, files=[
        file_entry(BASE + '/linked', b'elsewhere', kind=kind),
        file_entry(BASE + '/linked/index.d.ts', DECLARATION)])
    assert collect(document)['types']['status'] == 'unconfirmed'


def test_explicit_parent_directory_metadata_is_compatible_with_types():
    document = image({'types': 'linked/index.d.ts'}, files=[
        file_entry(BASE + '/linked', b'', kind='Directory'),
        file_entry(BASE + '/linked/index.d.ts', DECLARATION)])
    assert collect(document)['types']['status'] == 'confirmed'


@pytest.mark.parametrize('kind', ['SymbolicLink', 'HardLink', 'RegularFile'])
def test_type_owner_directory_cannot_itself_be_a_final_link_or_regular_file(kind):
    document = image({'types': 'index.d.ts'}, files=[
        file_entry(BASE, b'elsewhere', kind=kind), file_entry(BASE + '/index.d.ts', DECLARATION)])
    assert collect(document)['types']['status'] == 'unconfirmed'

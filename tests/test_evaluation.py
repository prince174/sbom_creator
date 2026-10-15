import json

import pytest

from sbom_creator.evaluation import compare
from sbom_creator.service import Request


def test_request_modes_do_not_mix_reference_and_production():
    args = {'repository_url': 'https://example.com/r.git', 'commit': 'a' * 40, 'image': 'example.com/app:1'}
    assert Request(**args).run_mode == 'production'
    with pytest.raises(ValueError):
        Request(**args, reference_sbom={})
    with pytest.raises(ValueError):
        Request(**args, run_mode='verification')


def test_reference_only_evaluates_completed_direct_edges(tmp_path):
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
           'metadata': {'component': {'type': 'application', 'name': 'app', 'version': '1',
                                     'bom-ref': 'root', 'purl': 'pkg:npm/app@1'}},
           'components': [{'type': 'library', 'name': 'dep', 'version': '2', 'bom-ref': 'dep', 'purl': 'pkg:npm/dep@2'}],
           'dependencies': [{'ref': 'root', 'dependsOn': ['dep']}]}
    actual = dict(bom, components=[bom['metadata']['component'], *bom['components']])
    (tmp_path / 'final.cdx.json').write_text(json.dumps(actual))
    direct = {'status': 'available', 'edges': [{'status': 'DIRECT', 'owner_ref': 'root', 'component_ref': 'dep'}]}
    (tmp_path / 'direct-dependencies.json').write_text(json.dumps(direct))
    assert compare(tmp_path, bom)['status'] == 'UNKNOWN'
    result = compare(tmp_path, bom, 'runtime')
    assert (result['tp'], result['fp'], result['fn']) == (1, 0, 0)
    assert result['reference_used_as_analysis_input'] is False
    assert result['version_accuracy'] == 1
    actual['components'][1] = dict(actual['components'][1], purl='pkg:npm/dep@3')
    (tmp_path / 'final.cdx.json').write_text(json.dumps(actual))
    mismatch = compare(tmp_path, bom, 'runtime')
    assert (mismatch['tp'], mismatch['fp'], mismatch['fn']) == (0, 1, 1)
    assert mismatch['version_accuracy'] == 0
    assert mismatch['count_delta'] == 0
    assert mismatch['missing'] and mismatch['extra']

import io
import json
import tarfile

import pytest
from compare_no_lock import verify_variant


def write_tree(path, payload, lock=False):
    with tarfile.open(path, 'w') as archive:
        for name, data in [('app/package.json', payload)] + ([('app/package-lock.json', b'{}')] if lock else []):
            member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o644
            archive.addfile(member,io.BytesIO(data))


def test_no_lock_variant_proves_payload_and_rejects_other_changes(tmp_path):
    original=tmp_path/'original';work=tmp_path/'work';analysis=tmp_path/'analysis'
    for directory in (original,work,analysis):
        directory.mkdir()
    write_tree(original/'runtime-app.tar',b'{}',True)
    write_tree(work/'runtime-app.tar',b'{}')
    (analysis/'final.cdx.json').write_text(json.dumps({'components':[]}))
    proof=verify_variant(original,work,'unused-existing-export',analysis)
    assert proof['unchanged_nonlock_application_tree']
    assert proof['removed_lock_paths']==['package-lock.json']
    write_tree(work/'runtime-app.tar',b'{"changed":true}')
    with pytest.raises(ValueError,match='more than project lockfiles'):
        verify_variant(original,work,'unused-existing-export',analysis)

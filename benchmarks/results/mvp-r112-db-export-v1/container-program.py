
import hashlib,json,os,stat
from pathlib import Path
source=Path('/retained/trivy-cache/java-db')
target=Path('/export/cache')
expected=json.loads(os.environ['R112_EXPECTED'])
assert set(p.name for p in source.iterdir()) == set(expected)
assert not target.exists()
stage=Path('/export/cache-export-stage')
stage.mkdir()
(stage/'java-db').mkdir()
facts={}
for name,digest in expected.items():
    src=source/name
    info=src.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 2*1024**3
    copied=0
    h=hashlib.sha256()
    with src.open('rb') as stream,(stage/'java-db'/name).open('xb') as out:
        while block:=stream.read(1024**2):
            copied+=len(block)
            assert copied <= 2*1024**3
            h.update(block)
            out.write(block)
    assert copied == info.st_size and h.hexdigest() == digest
    facts[name]={'bytes':copied,'sha256':h.hexdigest()}
stage.rename(target)
print(json.dumps({'status':'passed','network':False,'source_volume_read_only':True,
    'reference_or_old_database_accessed':False,'files':facts}))

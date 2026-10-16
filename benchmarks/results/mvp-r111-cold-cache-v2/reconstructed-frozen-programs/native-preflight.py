
import hashlib, json, os, pathlib, sqlite3
import sbom_creator
from sbom_creator.image_java import java_database_cache as module

root = pathlib.Path('/workspace')
assert os.geteuid() == 10001 and not pathlib.Path('/var/run/docker.sock').exists()
assert not any(root.iterdir()), 'Preflight requires a new empty native volume'
package = pathlib.Path(sbom_creator.__file__).parent
installed = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(package.rglob('*')) if p.is_file()
             and '__pycache__' not in p.parts and p.suffix != '.pyc'}
assert installed == json.loads(os.environ['R111_EXPECTED_PACKAGE_HASHES'])
work = root / 'preflight'
work.mkdir()
metadata = {'Version':1,'UpdatedAt':'2020-01-01T00:00:00Z','NextUpdate':'2099-01-01T00:00:00Z'}
def populate(cache):
    target = cache / 'java-db'
    target.mkdir(parents=True)
    connection = sqlite3.connect(target / 'trivy-java.db')
    try:
        connection.executescript("""
            CREATE TABLE artifacts(id INTEGER PRIMARY KEY,group_id TEXT,artifact_id TEXT);
            CREATE TABLE indices(artifact_id INTEGER,version TEXT,sha1 BLOB,archive_type TEXT,
              FOREIGN KEY(artifact_id) REFERENCES artifacts(id));
            CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id,group_id);
            CREATE INDEX indices_artifact_idx ON indices(artifact_id);
            CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1);
        """)
        connection.execute('INSERT INTO artifacts VALUES(1,?,?)',('org.synthetic','fixture'))
        connection.execute('INSERT INTO indices VALUES(1,?,?,?)',('0.0.0',bytes(20),'jar'))
        connection.commit()
    finally:
        connection.close()
    (target / 'metadata.json').write_text(json.dumps(metadata))
def files(path):
    return {p.relative_to(path).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob('*') if p.is_file()}
def forbidden(*args):
    raise AssertionError('Symlink or warm target must not invoke downloader')
passed = []
for location in ('cache-root','java-db','trivy-java.db','metadata.json'):
    case = work / location
    outside, cache = case / 'outside', case / 'cache'
    populate(outside)
    if location == 'cache-root':
        cache.symlink_to(outside, target_is_directory=True)
    elif location == 'java-db':
        cache.mkdir()
        (cache / 'java-db').symlink_to(outside / 'java-db', target_is_directory=True)
    else:
        populate(cache)
        item = cache / 'java-db' / location
        item.unlink()
        item.symlink_to(outside / 'java-db' / location)
    before = files(outside)
    try:
        module.ensure(cache, forbidden)
    except (ValueError,OSError,sqlite3.Error):
        pass
    else:
        raise AssertionError('Existing symlink accepted: ' + location)
    assert files(outside) == before
    assert (cache if location == 'cache-root' else cache / ('java-db' if location == 'java-db' else 'java-db/' + location)).is_symlink()
    passed.append('existing-symlink-' + location)
case = work / 'ancestor-symlink'
outside, linked_parent = case / 'outside', case / 'linked-parent'
outside.mkdir(parents=True)
linked_parent.symlink_to(outside, target_is_directory=True)
before = files(outside)
try:
    module.ensure(linked_parent / 'new-cache-child', forbidden)
except (ValueError,OSError,sqlite3.Error):
    pass
else:
    raise AssertionError('Symlink ancestor accepted')
assert files(outside) == before and not (outside / 'new-cache-child').exists()
assert linked_parent.is_symlink()
passed.append('symlink-ancestor-does-not-create-outside-child')
case = work / 'staged-symlink'
outside, cache = case / 'outside', case / 'cache'
populate(outside)
before = files(outside)
def linked(stage):
    (stage / 'java-db').symlink_to(outside / 'java-db', target_is_directory=True)
try:
    module.ensure(cache, linked)
except (ValueError,OSError,sqlite3.Error):
    pass
else:
    raise AssertionError('Staged symlink accepted')
assert files(outside) == before and not (cache / 'java-db').exists()
passed.append('staged-symlink-target-preserved')
for nonempty in (False, True):
    case = work / ('no-replace-' + str(nonempty))
    source, destination = case / 'source', case / 'destination'
    source.mkdir(parents=True)
    (source / 'candidate').write_bytes(b'synthetic incoming')
    destination.mkdir()
    if nonempty:
        (destination / 'sentinel').write_bytes(b'preserve existing')
    before, inode = files(destination), destination.stat().st_ino
    try:
        module.publish_noreplace(source, destination)
    except OSError:
        pass
    else:
        raise AssertionError('Existing directory was overwritten')
    assert files(destination) == before and destination.stat().st_ino == inode
    assert (source / 'candidate').read_bytes() == b'synthetic incoming'
    passed.append('atomic-no-replace-' + ('nonempty' if nonempty else 'empty'))
toy = work / 'toy-publication'
cold = module.ensure(toy, populate)
warm = module.ensure(toy, forbidden)
assert cold['java_database_cache_status'] == 'published' and warm['java_database_cache_status'] == 'reused'
assert cold['database_sha256'] == warm['database_sha256']
passed.append('atomic-positive-toy-cold-warm')
report = {'status':'passed','network':'none','uid':os.geteuid(),
          'installed_source_hashes':installed,'cases':passed,'skips':0,
          'synthetic_sqlite_only':True,'public_database_read_or_downloaded':False,
          'reference_accessed':False,'native_named_volume':True}
(root / 'preflight-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))

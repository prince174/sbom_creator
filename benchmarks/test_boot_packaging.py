import io
import zipfile

from label_boot_packaging import native_coordinates, oracle_hashes, payload_kind


def jar(entries):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w') as archive:
        for name,value in entries.items():archive.writestr(name,value)
    data.seek(0)
    return data


def test_metadata_resources_and_multirelease_classes_are_distinct():
    assert payload_kind(jar({'META-INF/MANIFEST.MF':b'header','LICENSE':b'license'}))=='metadata_only'
    assert payload_kind(jar({'META-INF/resources/webjars/example/a.js':b'alert(1)'}))=='resource_payload'
    assert payload_kind(jar({'META-INF/versions/17/A.class':b'\xca\xfe\xba\xbe'}))=='class_payload'
    assert payload_kind(jar({'Fake.class':b'not a class'}))=='metadata_only'


def test_filename_collision_does_not_pick_dependency_group():
    tree={'children':[{'groupId':group,'artifactId':'a','version':'1','type':'jar'} for group in ('first','second')]}
    assert native_coordinates(tree)['a-1.jar']=={('first','a','1'),('second','a','1')}


def test_primary_hash_collision_and_invalid_hash_are_not_unique_identity():
    def component(group, digest):
        return {'purl':'pkg:maven/'+group+'/a@1', 'hashes':[{'alg':'SHA-256','content':digest}]}
    index=oracle_hashes({'components':[component('first','a'*64),component('second','a'*64),component('invalid','x'*64)]})
    assert index['a'*64]=={'pkg:maven/first/a@1','pkg:maven/second/a@1'}
    assert 'x'*64 not in index

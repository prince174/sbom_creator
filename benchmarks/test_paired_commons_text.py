import io
import tarfile
import zipfile

import pytest
from paired_commons_text import verify_metadata


def fixture(path, dep_version="2"):
    with tarfile.open(path, "w") as archive:
        for name, version in (("app", "1"), ("dep", dep_version)):
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as jar:
                jar.writestr(f"META-INF/maven/g/{name}/pom.properties", f"groupId=g\nartifactId={name}\nversion={version}\n")
            raw = content.getvalue()
            member = tarfile.TarInfo(f"application/{name}.jar")
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    bom = {"metadata": {"component": {"bom-ref": "app", "group": "g", "name": "app", "version": "1"}},
           "components": [{"bom-ref": "dep", "group": "g", "name": "dep", "version": "2"}],
           "dependencies": [{"ref": "app", "dependsOn": ["dep"]}]}
    native = {"groupId": "g", "artifactId": "app", "version": "1", "children": [
        {"groupId": "g", "artifactId": "dep", "version": "2"}]}
    pom = b'<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>g</groupId><artifactId>dep</artifactId><version>2</version><scope>compile</scope></dependency></dependencies></project>'
    return bom, native, pom


def test_three_way_reference_and_jar_match(tmp_path):
    path = tmp_path / "app.tar"
    assert verify_metadata(path, *fixture(path))["effective_pom_native_cyclonedx_agree"]


@pytest.mark.parametrize("case", ["owner", "graph", "provided", "jar_version"])
def test_conflicts_rejected(tmp_path, case):
    path = tmp_path / "app.tar"
    bom, native, pom = fixture(path, "3" if case == "jar_version" else "2")
    if case == "owner":
        native["artifactId"] = "other"
    elif case == "graph":
        native["children"] = []
    elif case == "provided":
        pom = pom.replace(b'compile', b'provided')
    with pytest.raises(ValueError):
        verify_metadata(path, bom, native, pom)

import pytest
from java_local_parent import chain


def pom(parent=""):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0">'
            '<groupId>g</groupId><artifactId>a</artifactId><version>1</version>' + parent + '</project>').encode()


def parent(path=None):
    relative = "" if path is None else f"<relativePath>{path}</relativePath>"
    return '<parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version>' + relative + '</parent>'


def test_default_local_parent():
    result = chain({"pom.xml": pom(), "child/pom.xml": pom(parent())}, "child/pom.xml")
    assert result["status"] == "LOCAL_CHAIN_FOUND"
    assert result["chain"] == ["child/pom.xml", "pom.xml"]


@pytest.mark.parametrize("path,reason", [
    ("", "local_lookup_disabled"), ("../../pom.xml", "outside_repository"),
    ("C:/pom.xml", "unsupported_path"), ("/pom.xml", "unsupported_path"),
    ("..\\pom.xml", "unsupported_path"), ("${parent}", "unsupported_path"),
    ("../missing.xml", "missing_local_parent"),
])
def test_path_boundaries(path, reason):
    assert chain({"child/pom.xml": pom(parent(path))}, "child/pom.xml")["reason"] == reason


def test_cycle_and_limit():
    assert chain({"pom.xml": pom(parent("pom.xml"))}, "pom.xml")["reason"] == "cycle"
    assert chain({"pom.xml": pom()}, "pom.xml", limit=0)["reason"] == "depth_limit"


def test_wrong_parent_identity():
    blobs = {"pom.xml": pom().replace(b"<version>1", b"<version>2"), "child/pom.xml": pom(parent())}
    assert chain(blobs, "child/pom.xml")["reason"] == "unresolved_or_mismatched_identity"


def test_parent_directory():
    assert chain({"base/pom.xml": pom(), "child/pom.xml": pom(parent("../base"))},
                 "child/pom.xml")["status"] == "LOCAL_CHAIN_FOUND"


@pytest.mark.parametrize("raw", [b"broken", b"<!DOCTYPE project><project/>", b"x" * (1024 * 1024 + 1)],
                         ids=["malformed", "doctype", "oversized"])
def test_rejects_unsupported_xml(raw):
    assert chain({"pom.xml": raw}, "pom.xml")["reason"] == "invalid_pom"

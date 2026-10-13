import pytest
from java_scope_j1 import scope_candidates


def pom(scope="", extra="", version="1.0"):
    return (f'<project xmlns="http://maven.apache.org/POM/4.0.0">{extra}'
            '<dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId>'
            f'<version>{version}</version>{scope}</dependency></dependencies></project>').encode()


@pytest.mark.parametrize("scope,status", [
    ("", "RUNTIME_SCOPE_CANDIDATE"),
    ("compile", "RUNTIME_SCOPE_CANDIDATE"),
    ("runtime", "RUNTIME_SCOPE_CANDIDATE"),
    ("test", "NON_RUNTIME_SCOPE"),
    ("provided", "NON_RUNTIME_SCOPE"),
    ("system", "UNKNOWN"),
    ("other", "UNKNOWN"),
])
def test_scope_alone_never_proves_edge(scope, status):
    result = scope_candidates(pom(f"<scope>{scope}</scope>" if scope else ""))
    assert result["rows"][0]["status"] == status
    assert result["direct_edges"] == []
    assert result["rows"][0]["direct_edge_proven"] is False


@pytest.mark.parametrize("extra", [
    "<parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent>",
    "<profiles><profile><id>changes-scope</id></profile></profiles>",
    ("<dependencyManagement><dependencies><dependency><artifactId>library</artifactId>"
     "<scope>provided</scope></dependency></dependencies></dependencyManagement>"),
    "<modules><module>child</module></modules>",
], ids=["parent", "profile", "management", "module"])
def test_unresolved_model_blocks_even_explicit_runtime(extra):
    result = scope_candidates(pom("<scope>runtime</scope>", extra))
    assert result["rows"][0]["status"] == "UNKNOWN"
    assert result["rows"][0]["effective_scope"] is None


def test_version_expression_not_resolved_from_image():
    assert scope_candidates(pom(version="${library.version}"))["rows"][0]["status"] == "UNKNOWN"

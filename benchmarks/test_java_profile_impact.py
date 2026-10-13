import pytest
from java_profile_impact import audit


def pom(body):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0">' + body + '</project>').encode()


@pytest.mark.parametrize("section", ["dependencies", "dependencyManagement"])
def test_profile_can_change_graph(section):
    result = audit([pom(f"<profiles><profile><id>x</id><{section}/></profile></profiles>")])
    assert result["profiles"][0]["declaration_impact"] == "POTENTIAL"


def test_indirect_property_across_parent_child():
    root = pom('<properties><v>${base}</v><base>${v}</base></properties>'
               '<profiles><profile><id>x</id><properties><base>2</base></properties></profile></profiles>')
    child = pom('<dependencies><dependency><version>${v}</version></dependency></dependencies>')
    result = audit([root, child])
    assert result["profiles"][0]["properties_affecting_declarations"] == ["base"]
    assert result["direct_edges"] == []


def test_build_only_is_not_declared_safe():
    result = audit([pom('<profiles><profile><id>build</id><build/></profile></profiles>')])
    assert result["profiles"][0]["declaration_impact"] == "NO_STATIC_REFERENCE_FOUND"
    assert result["profiles"][0]["activation"] == "UNKNOWN"
    assert result["effective_model_resolved"] is False

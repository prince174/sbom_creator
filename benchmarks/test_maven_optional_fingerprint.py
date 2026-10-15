from maven_optional_fingerprint import optional_declarations


def test_only_explicit_root_optional_runtime_and_local_version():
    raw = b'''<project xmlns="http://maven.apache.org/POM/4.0.0">
<properties><v>1.2</v></properties><dependencies>
<dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version><optional>true</optional></dependency>
<dependency><groupId>g</groupId><artifactId>test</artifactId><version>1</version><optional>true</optional><scope>test</scope></dependency>
<dependency><groupId>g</groupId><artifactId>unknown</artifactId><version>${parent.v}</version><optional>true</optional></dependency>
</dependencies><profiles><profile><dependencies><dependency><groupId>g</groupId><artifactId>profile</artifactId><version>1</version><optional>true</optional></dependency></dependencies></profile></profiles></project>'''
    assert optional_declarations(raw) == [('g', 'a', '1.2')]


def test_repository_path_injection_not_resolved():
    raw = b'''<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>
<dependency><groupId>g</groupId><artifactId>../../escape</artifactId><version>1</version><optional>true</optional></dependency>
</dependencies></project>'''
    assert optional_declarations(raw) == []

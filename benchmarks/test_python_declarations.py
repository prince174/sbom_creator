from audit_python_declarations import declarations


def test_build_requirements_are_not_runtime_declarations():
    result = declarations({"project": {"name": "x"}, "build-system": {"requires": ["setuptools"]}})
    assert result["names"] == []
    assert result["build_requirements_count"] == 1


def test_dynamic_with_static_prefix_remains_unknown():
    result = declarations({"project": {"dependencies": ["a"], "dynamic": ["dependencies"]}})
    assert result["status"] == "UNKNOWN"
    assert result["names"] is None


def test_missing_project_is_not_empty_dependencies():
    assert declarations({})["names"] is None


def test_markers_extras_urls_are_not_silently_evaluated():
    result = declarations({"project": {"dependencies": ["A_B[x]>=1; python_version<'3.12'",
                                                        "d @ https://example.test/pkg.whl"],
                                       "optional-dependencies": {"test": ["pytest"]}}})
    assert result["names"] == ["a-b", "d"]
    assert result["conditional_count"] == result["extras_count"] == result["url_count"] == 1
    assert result["optional_groups"] == 1


def test_bad_map_is_unknown():
    assert declarations({"project": {"dependencies": {"x": "1"}}})["status"] == "UNKNOWN"

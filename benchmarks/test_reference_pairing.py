import pytest
from audit_reference_pairing import coordinate, observation, read


def test_python_distribution_names_normalize_but_versions_do_not():
    assert coordinate("pkg:pypi/Markup_Safe@3.0.4") == coordinate("pkg:pypi/markup-safe@3.0.4")
    expected = coordinate("pkg:pypi/markupsafe@3.0.4")
    old = "pkg:pypi/markupsafe@3.0.3"
    assert observation(expected, [(old, coordinate(old))])["state"] == "other_version_only"


def test_same_coordinate_retains_distinct_qualifiers_as_evidence():
    expected = coordinate("pkg:maven/org.example/demo@1?type=jar")
    actual = "pkg:maven/org.example/demo@1?classifier=sources&type=jar"
    result = observation(expected, [(actual, coordinate(actual))])
    assert result == {"state": "same_coordinate", "purls": [actual]}
    assert "pair_verified" not in result


def test_unknown_version_is_not_a_match():
    assert observation(coordinate("pkg:npm/demo"), [])["state"] == "reference_coordinate_unresolved"


def test_namespace_collision_is_not_version_drift():
    expected = coordinate("pkg:maven/org.first/demo@1")
    actual = "pkg:maven/org.second/demo@2"
    assert observation(expected, [(actual, coordinate(actual))])["state"] == "not_observed"


def test_tampered_receipt_fails_closed(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="hash mismatch"):
        read(path, "0" * 64)

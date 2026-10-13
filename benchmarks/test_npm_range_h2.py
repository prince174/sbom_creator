import pytest
from npm_range_h2 import satisfies


@pytest.mark.parametrize("version,spec,expected", [
    ("1.9.9", "^1.2.3", True), ("2.0.0", "^1.2.3", False),
    ("1.2.2", "^1.2.3", False), ("0.2.9", "^0.2.3", True),
    ("0.3.0", "^0.2.3", False), ("0.0.4", "^0.0.3", False),
    ("0.0.3", "^0.0.3", True), ("0.0.1", "^0.0.0", False),
    ("0.0.0", "^0.0.0", True), ("0.0.9", "~0.0.3", True),
    ("0.1.0", "~0.0.3", False), ("1.2.3", "1.2.3", True),
    ("1.2.4", "1.2.3", False),
])
def test_boundaries(version, spec, expected):
    assert satisfies(version, spec) is expected


@pytest.mark.parametrize("value", [None, 123, "", "1.2", "01.2.3", "1.2.3-rc.1",
                                  "1.2.3+build", "v1.2.3", "1.2.٣", "9" * 300,
                                  "9007199254740991.0.0", "9007199254740992.0.0"])
def test_unsupported_version(value):
    assert satisfies(value, "^1.2.3") is None


@pytest.mark.parametrize("spec", ["*", "^1.2", "~1", ">=1.0.0", "1 || 2", "npm:x@1.2.3",
                                 "workspace:*", "git+https://example.test/x", " ^1.2.3", None])
def test_unsupported_range_stays_unknown(spec):
    assert satisfies("1.2.3", spec) is None

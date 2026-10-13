import copy

import pytest
from test_python_direct import fixture
from test_python_mutations import cases

from sbom_creator.python_guard import classify


@pytest.mark.parametrize("name,source,image", list(cases()), ids=[c[0] for c in cases()])
def test_invalid_input_unknown(name, source, image):
    before = copy.deepcopy((source, image))
    result = classify(source, image)
    assert (source, image) == before
    if name == "valid":
        assert result["edges"][0]["status"] == "DIRECT"
    else:
        assert result["status"] == "UNKNOWN"
        assert result["edges"] == []
        assert result["coverage"] is None


def test_limits_and_no_raw_values():
    source, image = fixture()
    source["project"]["dependencies"] = ["dep>=2"] * 5001
    result = classify(source, image)
    assert result["status"] == "UNKNOWN"
    assert "dep>=2" not in str(result)

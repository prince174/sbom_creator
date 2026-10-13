import copy

import pytest
from audit_python_p1_inputs import cases
from python_p1_guard import classify as baseline
from python_p1_projection import classify
from test_python_direct_p1 import fixture


@pytest.mark.parametrize("name,source,image", list(cases()), ids=[c[0] for c in cases()])
def test_mutation_status_preserved(name, source, image):
    before = copy.deepcopy((source, image))
    result = classify(source, image)
    expected = baseline(source, image)
    assert result["status"] == expected["status"]
    assert result["edges"] == expected["edges"]
    assert (source, image) == before


def test_unused_large_fields_do_not_remove_evidence():
    source, image = fixture()
    expected = baseline(source, image)
    image["files"] = ["unused"] * 300000
    image["artifacts"][0]["metadata"]["unused"] = "x" * 17000000
    assert classify(source, image) == expected


def test_duplicates_other_languages_preserved():
    source, image = fixture()
    image["artifacts"].append({"id": "dep", "type": "npm"})
    assert classify(source, image)["status"] == "UNKNOWN"


def test_second_python_candidate_not_filtered():
    source, image = fixture()
    duplicate = copy.deepcopy(image["artifacts"][1])
    duplicate["id"] = "other"
    image["artifacts"].append(duplicate)
    assert classify(source, image) == baseline(source, image)
    assert classify(source, image)["edges"][0]["status"] == "UNKNOWN"


def test_relevant_budget_never_truncates_to_success():
    source, image = fixture()
    image["artifacts"][0]["metadata"]["requiresDist"] = ["dep>=2"] * 300000
    assert classify(source, image)["status"] == "UNKNOWN"

import copy
import inspect

import npm_direct_h1
import npm_direct_h2
import pytest
from test_npm_direct_h1 import fixture


def test_only_matcher_changes_classification_code():
    assert inspect.getsource(npm_direct_h2.classify) == inspect.getsource(npm_direct_h1.classify)


@pytest.mark.parametrize("spec,version,status", [
    ("^1.2.3", "1.9.0", "DIRECT"), ("^1.2.3", "2.0.0", "UNKNOWN"),
    ("^0.2.3", "0.3.0", "UNKNOWN"), ("^0.2.3", "0.2.4", "DIRECT"),
    ("^0.0.3", "0.0.4", "UNKNOWN"), ("^0.0.3", "0.0.3", "DIRECT"),
    ("workspace:*", "1.2.3", "UNKNOWN"), ("^1.2.3", "1.3.0-rc.1", "UNKNOWN")])
def test_caret_with_image_evidence(spec, version, status):
    package, image = fixture()
    package["dependencies"]["dep"] = spec
    image["artifacts"][1]["version"] = version
    before = copy.deepcopy((package, image))
    assert npm_direct_h2.classify(package, image)["edges"][0]["status"] == status
    assert (package, image) == before


@pytest.mark.parametrize("path", ["/usr/local/lib/node_modules/dep/package.json",
                                  "/srv/node_modules/other/node_modules/dep/package.json"])
def test_caret_does_not_promote_unrelated_locations(path):
    package, image = fixture()
    package["dependencies"]["dep"] = "^1.2.3"
    image["artifacts"][1]["locations"][0]["path"] = path
    assert npm_direct_h2.classify(package, image)["edges"][0]["status"] == "UNKNOWN"

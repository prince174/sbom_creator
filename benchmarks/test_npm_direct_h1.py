import copy

import pytest
from npm_direct_h1 import classify, satisfies


def fixture():
    def artifact(name, version, path):
        return {"id": path, "name": name, "version": version, "type": "npm",
                "locations": [{"path": path}]}
    return ({"name": "app", "version": "1.0.0", "dependencies": {"dep": "~1.2.3"}},
            {"artifacts": [artifact("app", "1.0.0", "/srv/package.json"),
                           artifact("dep", "1.2.9", "/srv/node_modules/dep/package.json")]})


@pytest.mark.parametrize("version,spec,expected", [
    ("1.2.9", "~1.2.3", True), ("1.3.0", "~1.2.3", False),
    ("1.2.2", "~1.2.3", False), ("1.2.3", "1.2.3", True),
    ("1.2.4", "1.2.3", False), ("1.2.3-rc.1", "~1.2.3", None),
    ("1.2.3", "^1.2.0", None), ("1.2.3", "npm:other@1.2.3", None),
    ("1.2.3", "~1.2", None), ("01.2.3", "1.2.3", None)])
def test_ranges(version, spec, expected):
    assert satisfies(version, spec) is expected


def test_direct_and_no_input_mutation():
    package, image = fixture()
    before = copy.deepcopy((package, image))
    result = classify(package, image)
    assert result["edges"][0]["status"] == "DIRECT"
    assert result["edges"][0]["version"] == "1.2.9"
    assert (package, image) == before


@pytest.mark.parametrize("case", ["base", "nested", "ambiguous_root", "ambiguous_version",
                                 "symlink", "optional", "workspace", "override", "missing"])
def test_unsupported_or_ambiguous_stays_unknown(case):
    package, image = fixture()
    dep = image["artifacts"][1]
    if case == "base":
        dep["locations"][0]["path"] = "/usr/local/lib/node_modules/dep/package.json"
    elif case == "nested":
        dep["locations"][0]["path"] = "/srv/node_modules/parent/node_modules/dep/package.json"
    elif case == "ambiguous_root":
        root = copy.deepcopy(image["artifacts"][0])
        root["locations"][0]["path"] = "/other/package.json"
        image["artifacts"].append(root)
    elif case == "ambiguous_version":
        other = copy.deepcopy(dep)
        other["version"] = "1.2.8"
        image["artifacts"].append(other)
    elif case == "symlink":
        dep["locations"][0]["accessPath"] = "/different/package.json"
    elif case == "optional":
        package["optionalDependencies"] = {"dep": "2.0.0"}
    elif case == "workspace":
        package["workspaces"] = ["packages/*"]
    elif case == "override":
        package["overrides"] = {"dep": "1.2.9"}
    else:
        image["artifacts"].pop()
    assert classify(package, image)["edges"][0]["status"] == "UNKNOWN"


def test_dev_and_transitive_not_promoted():
    package, image = fixture()
    package["devDependencies"] = {"dev": "1.0.0"}
    extra = copy.deepcopy(image["artifacts"][1])
    extra.update(name="transitive")
    extra["locations"][0]["path"] = "/srv/node_modules/transitive/package.json"
    image["artifacts"].append(extra)
    assert [r["name"] for r in classify(package, image)["edges"]] == ["dep"]

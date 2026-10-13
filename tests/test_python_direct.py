import copy

import pytest

from sbom_creator.python_direct import classify


def fixture():
    def artifact(name, version):
        return {"id": name, "name": name, "version": version, "type": "python", "metadataType": "python-package",
                "metadata": {}, "locations": [{"path": f"/venv/lib/python3.12/site-packages/{name}.dist-info/METADATA"}]}
    source = {"project": {"name": "app", "dynamic": ["version"], "dependencies": ["dep>=2"]}}
    root, dep = artifact("app", "1.0"), artifact("dep", "2.1")
    root["metadata"]["requiresDist"] = ["dep>=2", "optional; extra == 'x'"]
    return source, {"artifacts": [root, dep]}


def test_direct_dynamic_root_version_not_invented():
    source, image = fixture()
    before = copy.deepcopy((source, image))
    result = classify(source, image)
    assert result["edges"][0]["status"] == "DIRECT"
    assert result["root_version_from_source"] is None
    assert result["installed_root_version"] == "1.0"
    assert (source, image) == before


@pytest.mark.parametrize("case", ["other_venv", "ambiguous", "missing_metadata", "conflict", "marker", "extras", "url", "root_version", "symlink"])
def test_uncertainty_stays_unknown(case):
    source, image = fixture()
    root, dep = image["artifacts"]
    if case == "other_venv":
        dep["locations"][0]["path"] = dep["locations"][0]["path"].replace("/venv/", "/other/")
    elif case == "ambiguous":
        image["artifacts"].append(copy.deepcopy(dep))
    elif case == "missing_metadata":
        root["metadata"] = {}
    elif case == "conflict":
        dep["version"] = "1.9"
    elif case == "marker":
        source["project"]["dependencies"] = ["dep>=2; python_version >= '3.0'"]
    elif case == "extras":
        source["project"]["dependencies"] = ["dep[x]>=2"]
    elif case == "url":
        source["project"]["dependencies"] = ["dep @ https://example.test/pkg.whl"]
    elif case == "root_version":
        source["project"]["version"] = "9.0"
    else:
        dep["locations"][0]["accessPath"] = "/outside/METADATA"
    assert classify(source, image)["edges"][0]["status"] == "UNKNOWN"


def test_dynamic_dependencies_unknown_and_no_build_promotion():
    source, image = fixture()
    source["project"]["dynamic"].append("dependencies")
    source["build-system"] = {"requires": ["flit_core"]}
    result = classify(source, image)
    assert result["status"] == "UNKNOWN"
    assert result["edges"] == []

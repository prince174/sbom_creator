from copy import deepcopy

import pytest
from java_gav_evidence import match

OWNER = ("g", "app", "1")
DEP = ("g", "lib", "2")


def artifact(identity, coordinate):
    group, name, version = coordinate
    return {"id": identity, "type": "java-archive", "version": version,
            "metadata": {"pomProperties": {"groupId": group, "artifactId": name, "version": version}},
            "locations": [{"path": "\\module\\pom.xml", "accessPath": "\\module\\pom.xml"}]}


def catalogs():
    source = {"artifacts": [artifact("a", OWNER), artifact("b", DEP)],
              "artifactRelationships": [{"type": "dependency-of", "parent": "b", "child": "a"}]}
    return source, deepcopy(source)


def test_corroboration_does_not_prove_direct_scope():
    result = match(*catalogs(), OWNER, DEP, "module/pom.xml")
    assert result["status"] == "CORROBORATED_CANDIDATE"
    assert result["effective_scope"] is None
    assert result["direct_edge_proven"] is False


@pytest.mark.parametrize("mutation", ["duplicate_id", "duplicate_gav", "version", "module", "reverse", "conflict", "artifact_version"])
def test_counterexamples(mutation):
    source, image = catalogs()
    if mutation in ("duplicate_id", "duplicate_gav"):
        copy = deepcopy(image["artifacts"][1])
        if mutation == "duplicate_gav":
            copy["id"] = "other"
        image["artifacts"].append(copy)
    elif mutation == "version":
        image["artifacts"][1]["metadata"]["pomProperties"]["version"] = "3"
    elif mutation == "module":
        source["artifacts"][1]["locations"][0]["path"] = "/other/pom.xml"
    elif mutation == "reverse":
        source["artifactRelationships"][0].update(parent="a", child="b")
    elif mutation == "conflict":
        image["artifacts"][1]["metadata"]["pomProject"] = {"groupId": "other", "artifactId": "lib", "version": "2"}
    elif mutation == "artifact_version":
        image["artifacts"][1]["version"] = "3"
    assert match(source, image, OWNER, DEP, "module/pom.xml")["status"] == "UNKNOWN"

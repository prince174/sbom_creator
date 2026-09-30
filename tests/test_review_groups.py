import copy

import pytest
from test_core import doc, package

from sbom_creator.core import reconcile, review_report


def test_review_groups_preserve_all_uncertainty_without_inferring_runtime_scope():
    source = doc(package("dev", "dev"), package("old", "versioned", "1"),
                 package("bad-source", "source-bad", purl="pkg:pypi/wrong@1.2.3"),
                 package("ci", "actions/checkout", "v4", type="github-action",
                         purl="pkg:github/actions/checkout@v4", foundBy="github-actions-usage-cataloger"))
    image = doc(package("new", "versioned", "2"),
                package("bad-image", "image-bad", purl="pkg:pypi/wrong@1.2.3"),
                package("orphan", "orphan"),
                package("lock", "declared", foundBy="python-package-cataloger"),
                package("signature", "binary", type="binary", purl="pkg:generic/binary@1.2.3",
                        foundBy="binary-classifier-cataloger"))
    result = reconcile(source, image, payload_evidence={"new": {"status": "confirmed", "path": "/app/code.py"}})
    before = copy.deepcopy(result)
    report = review_report(result["decisions"])
    assert report["unknown_count"] == 8
    assert report["group_counts"] == {group: 1 for group in (
        "source_declarations", "version_mismatch", "source_identity", "ci_configuration",
        "image_identity", "image_payload", "image_declarations", "image_evidence")}
    assert sum(report["observation_counts"].values()) == 8
    assert all(item["dependency_scope"] == "not_established" for item in report["items"])
    assert result == before
    assert [a["id"] for a in result["selected_syft"]["artifacts"]] == ["new"]


def test_review_distinguishes_os_package_from_language_package():
    image = doc(package("os", "lib", type="deb", purl="pkg:deb/debian/wrong@1.2.3", foundBy="dpkg-db-cataloger"),
                package("python", "lib", purl="pkg:pypi/wrong@1.2.3"))
    report = review_report(reconcile(doc(), image)["decisions"])
    assert {tuple(item["package_kinds"]) for item in report["items"]} == {("os_package",), ("language_package",)}
    assert report["group_counts"] == {"image_identity": 2}


def test_legacy_review_can_still_be_verified_but_unknown_schemas_fail():
    decisions = reconcile(doc(package("dev")), doc())["decisions"]
    legacy = review_report(decisions, schema_version=1)
    assert set(legacy) == {"schema_version", "unknown_count", "reason_counts", "items", "scope"}
    assert "review_group" not in legacy["items"][0]
    for version in (None, True, 0, 3, "2"):
        with pytest.raises(ValueError, match="schema"):
            review_report(decisions, schema_version=version)

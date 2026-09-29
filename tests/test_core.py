import copy
import math

import pytest

from sbom_creator.core import artifact_identity, build_candidates, reconcile, rules_assessor


def package(pid, name="example", version="1.2.3", **overrides):
    return {"id": pid, "name": name, "version": version, "type": "python",
            "purl": f"pkg:pypi/{name}@{version}", "foundBy": "python-installed-package-cataloger",
            "locations": [{"path": f"/site-packages/{name}.dist-info/METADATA"}], **overrides}


def doc(*packages, **overrides):
    return {"artifacts": list(packages), "artifactRelationships": [], "files": [],
            "source": {"id": "image-source"}, **overrides}


def scores(score=99, *, cite=True, missing=None):
    def assess(candidates):
        return [{"candidate_id": c["candidate_id"], "tp_score": score, "reason": "Reviewed observed metadata",
                 "evidence_ids": [e["id"] for e in c["evidence"]] if cite else [],
                 "missing_evidence": missing or []} for c in candidates]
    return assess


def test_exact_purl_uses_local_ids_and_qualifier_normalization():
    source = doc(package("same-id", purl="pkg:pypi/Example@1.2.3?distro=debian&arch=amd64"))
    image = doc(package("different-id", purl="pkg:pypi/example@1.2.3?arch=amd64&distro=debian"))
    result = reconcile(source, image, rules_assessor)
    assert len(result["decisions"]) == 1
    decision = result["decisions"][0]
    assert decision["category"] == "exact_match"
    assert decision["decision"] == "INCLUDE"
    assert decision["tp_score"] is None
    assert {e["origin"] for e in decision["evidence"]} == {"source", "image"}
    assert len({e["document_sha256"] for e in decision["evidence"]}) == 2
    assert result["selected_syft"]["artifacts"][0]["id"] == "different-id"


def test_union_preserves_exact_versions_and_image_only_os_packages():
    source = doc(package("s1", version="1"), package("s2", "source-only"))
    image = doc(package("i1", version="2"), package("i2", version="3"),
                package("os", "libc6", "2.36", type="deb", purl="pkg:deb/debian/libc6@2.36?arch=amd64",
                        foundBy="dpkg-db-cataloger"))
    result = reconcile(source, image, scores())
    assert result["coverage"]["decisions"] == {"INCLUDE": 3, "EXCLUDE": 0, "UNKNOWN": 2}
    assert {a["version"] for a in result["selected_syft"]["artifacts"] if a["name"] == "example"} == {"2", "3"}
    assert sum(d["category"] == "version_conflict" for d in result["decisions"]) == 3
    assert all(d["decision"] == "UNKNOWN" for d in result["decisions"] if not d["image_artifact_ids"])


def test_fallback_is_exact_and_normalizes_python_name():
    source = doc(package("s", "Hello.World", purl=""))
    image = doc(package("i", "hello-world"))
    assert len(build_candidates(source, image)) == 1
    changed = doc(package("i", "hello-world", version="1.2.4"))
    assert len(build_candidates(source, changed)) == 2
    assert not artifact_identity(package("j", purl="", type="java-archive"))["identity_valid"]


def test_qualifiers_namespace_and_case_sensitive_names_do_not_collapse():
    artifacts = [package("a", purl="pkg:pypi/example@1.2.3?arch=amd64"),
                 package("b", purl="pkg:pypi/example@1.2.3?arch=arm64"),
                 package("c", "Hello", type="java-archive", purl="pkg:maven/org.a/Hello@1.2.3"),
                 package("d", "Hello", type="java-archive", purl="pkg:maven/org.b/Hello@1.2.3"),
                 package("e", "hello", type="java-archive", purl="pkg:maven/org.a/hello@1.2.3")]
    assert len(build_candidates(doc(), doc(*artifacts))) == 5


@pytest.mark.parametrize("purl,version", [("pkg:pypi/example@%5E1.2", "^1.2"),
                                          ("pkg:pypi/example", ""),
                                          ("pkg:pypi/example@1.2.4", "1.2.3"),
                                          ("not-a-purl", "1"),
                                          ("pkg:pypi/example@1.2.3?arch=a&arch=b", "1.2.3")])
def test_ambiguous_identity_never_included_even_high_score(purl, version):
    result = reconcile(doc(), doc(package("i", purl=purl, version=version)), scores(100))
    assert result["decisions"][0]["decision"] == "UNKNOWN"
    assert result["selected_syft"]["artifacts"] == []


@pytest.mark.parametrize("score,expected", [(0, "EXCLUDE"), (70, "EXCLUDE"), (70.01, "INCLUDE"), (100, "INCLUDE")])
def test_strict_tp_threshold(score, expected):
    result = reconcile(doc(), doc(package("i")), scores(score))
    assert result["decisions"][0]["decision"] == expected


@pytest.mark.parametrize("score", [True, False, -1, 101, math.nan, math.inf, "99", None])
def test_invalid_scores_fail_closed(score):
    with pytest.raises(ValueError, match="finite"):
        reconcile(doc(), doc(package("i")), scores(score))


def test_source_evidence_is_not_image_evidence():
    source, image = doc(package("s")), doc(package("i"))
    def assessor(candidates):
        rows = scores()(candidates)
        for candidate, row in zip(candidates, rows):
            row["evidence_ids"] = [e["id"] for e in candidate["evidence"] if e["origin"] == "source"]
        return rows
    assert reconcile(source, image, assessor)["decisions"][0]["decision"] == "UNKNOWN"
    assert reconcile(source, image, scores(cite=False))["decisions"][0]["decision"] == "UNKNOWN"
    assert reconcile(source, image, scores(missing=["Conflicting package identity needs clarification"]))["decisions"][0]["decision"] == "UNKNOWN"


def test_copied_lockfile_in_image_does_not_establish_installed_package():
    image = doc(package("i", "serde", "1.0.0", type="rust-crate", purl="pkg:cargo/serde@1.0.0",
                        foundBy="rust-cargo-lock-cataloger", locations=[{"path": "/app/Cargo.lock"}]))
    assert reconcile(doc(), image, scores(100))["decisions"][0]["decision"] == "UNKNOWN"
    image["artifacts"][0]["foundBy"] = "cargo-auditable-binary-cataloger"
    assert reconcile(doc(), image, rules_assessor)["decisions"][0]["decision"] == "INCLUDE"


def test_copied_requirements_in_image_is_declaration_not_installed_package():
    image = doc(package("i", foundBy="python-package-cataloger", metadataType="python-pip-requirements-entry",
                        locations=[{"path": "/app/requirements.txt"}]))
    assert reconcile(doc(), image, scores(100))["decisions"][0]["decision"] == "UNKNOWN"


def test_root_package_json_and_installed_node_modules_are_image_package_metadata():
    image = doc(package("i", type="npm", purl="pkg:npm/example@1.2.3", foundBy="javascript-package-cataloger",
                        locations=[{"path": "/app/package.json"}]))
    assert reconcile(doc(), image, rules_assessor)["decisions"][0]["decision"] == "INCLUDE"
    image["artifacts"][0]["locations"] = [{"path": "/app/node_modules/example/package.json"}]
    assert reconcile(doc(), image, rules_assessor)["decisions"][0]["decision"] == "INCLUDE"
    image["artifacts"][0]["foundBy"] = "javascript-lock-cataloger"
    image["artifacts"][0]["locations"] = [{"path": "/app/package-lock.json"}]
    assert reconcile(doc(), image, scores(100))["decisions"][0]["decision"] == "UNKNOWN"


def test_missing_default_assessor_is_configuration_error():
    with pytest.raises(RuntimeError, match="fallback"):
        reconcile(doc(), doc())


def test_assessment_ids_and_evidence_must_be_complete_local_and_unique():
    image = doc(package("a"), package("b", "other"))
    def wrong_evidence(candidates):
        rows = scores()(candidates)
        rows[0]["evidence_ids"] = rows[1]["evidence_ids"]
        return rows
    with pytest.raises(ValueError, match="unknown or duplicate evidence"):
        reconcile(doc(), image, wrong_evidence)
    with pytest.raises(ValueError, match="every candidate"):
        reconcile(doc(), image, lambda candidates: scores()(candidates)[:-1])
    def duplicate(candidates):
        rows = scores()(candidates)
        return [rows[0], rows[0]]
    with pytest.raises(ValueError, match="duplicate candidate"):
        reconcile(doc(), image, duplicate)


def test_selected_image_preserves_file_ownership_and_prunes_dangling_edges():
    relationships = [{"parent": parent, "child": child, "type": relation} for parent, child, relation in (
        ("keep", "file", "contains"), ("drop", "file", "contains"),
        ("image-source", "keep", "contains"), ("keep", "drop", "dependency-of"),
        ("file", "file-two", "contains"), ("keep", "missing", "contains"))]
    image = doc(package("keep"), package("drop", "other"), artifactRelationships=relationships,
                files=[{"id": "file"}, {"id": "file-two"}])
    original = copy.deepcopy(image)
    def assessor(candidates):
        rows = scores()(candidates)
        for c, row in zip(candidates, rows):
            if "drop" in c["image_artifact_ids"]:
                row["tp_score"] = 70
        candidates[0]["evidence"][0]["artifact"]["name"] = "malicious assessor mutation"
        return rows
    result = reconcile(doc(), image, assessor)
    assert image == original
    selected = result["selected_syft"]
    assert selected["files"] == image["files"]
    assert [(r["parent"], r["child"]) for r in selected["artifactRelationships"]] == [
        ("keep", "file"), ("image-source", "keep"), ("file", "file-two")]
    assert result["coverage"]["relationships_pruned"] == 3


def test_document_local_duplicate_artifact_ids_fail():
    with pytest.raises(ValueError, match="unique"):
        build_candidates(doc(), doc(package("same"), package("same", "other")))


def test_unchanged_inputs_produce_stable_candidate_and_evidence_ids():
    source, image = doc(package("s")), doc(package("i"))
    assert reconcile(source, image, rules_assessor) == reconcile(source, image, rules_assessor)


def test_purl_disagreement_with_name_and_ecosystem_is_ambiguous():
    for changes in ({"name": "different"}, {"type": "npm"}):
        assert not artifact_identity(package("i", purl="pkg:pypi/example@1.2.3", **changes))["identity_valid"]


@pytest.mark.parametrize("version", ["3.0.20-1~deb12u2", "2:1.0~rc1-1", "1.2^20260929git"])
def test_internal_tilde_or_caret_in_exact_os_versions_is_preserved(version):
    image = doc(package("i", "openssl", version, type="deb",
                        purl=f"pkg:deb/debian/openssl@{version}", foundBy="dpkg-db-cataloger"))
    result = reconcile(doc(), image, rules_assessor)
    assert result["decisions"][0]["decision"] == "INCLUDE"
    assert result["selected_syft"]["artifacts"][0]["version"] == version


@pytest.mark.parametrize("version", ["~1.2", "^1.2", ">=1.2", "1.*"])
def test_version_constraints_still_never_become_exact(version):
    assert not artifact_identity(package("i", version=version))["identity_valid"]


def test_binary_generic_type_pairing_is_valid_but_signature_is_not_strong_metadata():
    image = doc(package("i", "python", "3.12.14", type="binary", purl="pkg:generic/python@3.12.14",
                        foundBy="binary-classifier-cataloger"))
    decision = reconcile(doc(), image, rules_assessor)["decisions"][0]
    assert decision["identity_valid"] is True
    assert decision["decision"] == "UNKNOWN"
    assert decision["policy_reason"] == "INSUFFICIENT_IMAGE_EVIDENCE"


@pytest.mark.parametrize("cataloger", ["java-jvm-cataloger", "graalvm-native-image-cataloger",
                                       "pe-binary-package-cataloger", "elf-binary-package-cataloger"])
def test_embedded_binary_metadata_is_image_evidence(cataloger):
    image = doc(package("i", "runtime", "1.2.3", type="binary", purl="pkg:binary/runtime@1.2.3",
                        foundBy=cataloger))
    assert reconcile(doc(), image, rules_assessor)["decisions"][0]["decision"] == "INCLUDE"

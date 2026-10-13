import copy
import json

import pytest

from sbom_creator.direct_evidence import annotate, load_manifest


def fixture():
    package = {"name": "app", "version": "1.0.0", "dependencies": {"dep": "^1.2.3"}}
    image = {"artifacts": [{"id": aid, "type": "npm", "name": name, "version": version,
                            "locations": [{"path": path}]} for aid, name, version, path in
                           [("root", "app", "1.0.0", "/app/package.json"),
                            ("dep", "dep", "1.2.9", "/app/node_modules/dep/package.json")]]}
    document = {"components": [{"bom-ref": "root"}, {"bom-ref": "dep"}], "dependencies": []}
    return package, image, document


def test_edges_preserve_inventory_and_inputs():
    package, image, document = fixture()
    before = copy.deepcopy((package, image))
    report = annotate(document, image, {"status": "available", "package": package})
    assert report["direct_count"] == 1
    assert document["dependencies"] == [{"ref": "root", "dependsOn": ["dep"]}]
    assert {c["bom-ref"] for c in document["components"]} == {"root", "dep"}
    assert (package, image) == before
    assert not report["build_usage_proven"]


def test_excluded_package_cannot_gain_direct_edge():
    package, image, document = fixture()
    document["components"].pop()
    report = annotate(document, image, {"status": "available", "package": package})
    assert report["unknown_count"] == 1
    assert document["dependencies"] == []


def test_no_credential_leak_in_unknown_spec():
    package, image, document = fixture()
    package["dependencies"]["dep"] = "git+https://user:SECRET@example.test/repo"
    report = annotate(document, image, {"status": "available", "package": package})
    assert "SECRET" not in json.dumps(report)
    assert report["unknown_count"] == 1


@pytest.mark.parametrize("raw", ['[]', '{"name":"a","name":"b"}',
                               '{"name":"a","version":"1","dependencies":[]}',
                               '{"name":"a","version":"1","dependencies":{"x":null}}',
                               '{', 'x' * (1024 * 1024 + 1)],
                         ids=["array", "duplicate", "bad-map", "bad-version", "broken-json", "oversized"])
def test_malformed_manifest_is_unknown(tmp_path, raw):
    (tmp_path / "package.json").write_text(raw)
    assert load_manifest(tmp_path)["status"] == "UNKNOWN"


def test_missing_manifest_is_not_applicable(tmp_path):
    assert load_manifest(tmp_path)["status"] == "not-applicable"


def test_directory_instead_of_manifest_is_unknown(tmp_path):
    (tmp_path / "package.json").mkdir()
    assert load_manifest(tmp_path)["status"] == "UNKNOWN"


def test_symlink_manifest_is_not_read(tmp_path):
    target = tmp_path / "private.json"
    target.write_text('{"name":"secret","version":"1.0.0"}')
    try:
        (tmp_path / "package.json").symlink_to(target)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    report = load_manifest(tmp_path)
    assert report["status"] == "UNKNOWN"
    assert "secret" not in json.dumps(report)

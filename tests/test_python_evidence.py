import copy
import json

from test_python_direct import fixture

from sbom_creator.python_evidence import annotate, combine


def test_publish_preserves_inventory_and_existing_edges():
    source, image = fixture()
    original = copy.deepcopy((source, image))
    cdx = {"components": [{"bom-ref": "app"}, {"bom-ref": "dep"}],
           "dependencies": [{"ref": "app", "dependsOn": ["existing"]}]}
    report = annotate(cdx, image, {"status": "available", "document": source})
    assert report["direct_count"] == 1
    assert cdx["dependencies"][0]["dependsOn"] == ["dep", "existing"]
    assert len(cdx["components"]) == 2
    assert (source, image) == original
    assert "document" not in report


def test_missing_selected_target_does_not_invent_component():
    source, image = fixture()
    cdx = {"components": [{"bom-ref": "app"}]}
    result = annotate(cdx, image, {"status": "available", "document": source})
    assert result["unknown_count"] == 1
    assert result["direct_count"] == 0
    assert "dependencies" not in cdx


def test_url_not_disclosed():
    source, image = fixture()
    source["project"]["dependencies"] = ["dep @ https://user:SECRET@example.test/pkg.whl"]
    result = annotate({"components": []}, image, {"status": "available", "document": source})
    assert "SECRET" not in json.dumps(result)
    assert result["unknown_count"] == 1


def test_npm_absent_python_and_mixed_profiles():
    npm = {"status": "evaluated", "edges": [{"status": "DIRECT"}]}
    assert combine(npm, {"status": "not-applicable"}) is npm
    python = {"status": "UNKNOWN", "edges": []}
    result = combine(npm, python)
    assert result["direct_count"] == 1
    assert result["unknown_count"] is None
    assert len(result["profiles"]) == 2




def test_local_analysis_automatically_reads_python_manifest(tmp_path, monkeypatch):
    from sbom_creator import pipeline
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname='app'\nversion='1.0'\ndependencies=[]")
    monkeypatch.setattr(pipeline, "scan_source", lambda *a: {})
    monkeypatch.setattr(pipeline, "scan_image", lambda *a: ({}, {}))
    def publish(*args):
        assert args[6]["status"] == "not-applicable"
        assert args[7]["document"]["project"]["name"] == "app"
        return {"status": "succeeded"}
    monkeypatch.setattr(pipeline, "publish_catalogs", publish)
    assert pipeline.analyze_local(source, "docker.io/example/app:1", tmp_path / "result")["status"] == "succeeded"

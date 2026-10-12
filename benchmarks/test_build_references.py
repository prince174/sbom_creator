"""Reference graph integrity and distinction between absent and empty graphs."""
import json

import build_references as refs
import pytest


def bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "library", "name": "project", "bom-ref": "root"}},
            "components": [{"type": "library", "name": "direct", "bom-ref": "a"}],
            "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": []}]}


def inspect(tmp_path, monkeypatch, data):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(refs, "ROOT", tmp_path)
    return refs.inspect_bom(path)


def test_direct_edge_is_not_component_count(tmp_path, monkeypatch):
    result = inspect(tmp_path, monkeypatch, bom())
    assert result["components"] == 2
    assert result["direct_edges"] == 1
    assert result["schema_valid"]


def test_missing_graph_is_not_zero_dependencies(tmp_path, monkeypatch):
    data = bom()
    del data["dependencies"]
    result = inspect(tmp_path, monkeypatch, data)
    assert not result["root_graph_present"]
    assert result["direct_edges"] is None


def test_explicit_empty_graph(tmp_path, monkeypatch):
    data = bom()
    data["dependencies"][0]["dependsOn"] = []
    result = inspect(tmp_path, monkeypatch, data)
    assert result["root_graph_present"]
    assert result["direct_edges"] == 0


def test_dangling_edge_rejected(tmp_path, monkeypatch):
    data = bom()
    data["dependencies"][0]["dependsOn"] = ["missing"]
    with pytest.raises(ValueError, match="dangling"):
        inspect(tmp_path, monkeypatch, data)


def test_duplicate_identity_rejected(tmp_path, monkeypatch):
    data = bom()
    data["components"].append({"type": "library", "name": "another", "bom-ref": "a"})
    with pytest.raises(ValueError, match="duplicate"):
        inspect(tmp_path, monkeypatch, data)

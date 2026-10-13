import hashlib
import io
import json
import tarfile

import pytest
from freeze_direct_split import partition
from paired_express import application_tree, archive_binding, npm_component_name, root_dependencies


def test_npm_scoped_component_name():
    assert npm_component_name({"group": "@scope", "name": "lib"}) == "@scope/lib"
    assert npm_component_name({"name": "lib"}) == "lib"


def test_empty_root_is_not_missing_root():
    document = {"metadata": {"component": {"bom-ref": "root"}}, "dependencies": [{"ref": "root"}]}
    assert root_dependencies(document) == []
    document["dependencies"] = []
    with pytest.raises(ValueError, match="missing or ambiguous"):
        root_dependencies(document)
    document["dependencies"] = [{"ref": "root"}, {"ref": "root"}]
    with pytest.raises(ValueError, match="missing or ambiguous"):
        root_dependencies(document)


def make_tar(path, root, content, mode=0o644):
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo(root + "/package.json")
        member.size = len(content)
        member.mode = mode
        archive.addfile(member, io.BytesIO(content))


def test_application_tree_ignores_only_export_root_for_content_comparison(tmp_path):
    a, b = tmp_path / "a.tar", tmp_path / "b.tar"
    make_tar(a, "src", b"old")
    make_tar(b, "app", b"old")
    assert application_tree(a) == application_tree(b)
    make_tar(b, "app", b"new")
    assert application_tree(a) != application_tree(b)
    make_tar(b, "app", b"old", 0o600)
    assert application_tree(a) != application_tree(b)


def test_partition_is_order_independent_disjoint_and_nonempty():
    rows = [{"id": f"{language}-{i}", "language": language, "direct_edges": int(i < 5)}
            for language in ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby") for i in range(10)]
    result = partition(rows)
    assert result == partition(list(reversed(rows)))
    assert len(result["holdout"]) == 12
    assert len(result["development"]) == 48
    assert not set(result["holdout"]) & set(result["development"])
    by_id = {r["id"]: r for r in rows}
    for language in {r["language"] for r in rows}:
        selected = [by_id[key] for key in result["holdout"] if by_id[key]["language"] == language]
        assert len(selected) == 2
        assert sum(r["direct_edges"] for r in selected) == 1


def oci_archive(path, corrupt=False, ambiguous=False):
    blobs = {}
    def add(value):
        raw = json.dumps(value).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        blobs["blobs/sha256/" + digest.split(":")[1]] = raw
        return {"digest": digest, "size": len(raw)}
    config = add({"os": "linux", "architecture": "amd64", "rootfs": {"diff_ids": []}})
    manifest = add({"config": config})
    manifest["platform"] = {"os": "linux", "architecture": "amd64"}
    index = add({"manifests": [manifest, manifest] if ambiguous else [manifest]})
    blobs["index.json"] = json.dumps({"manifests": [index]}).encode()
    if corrupt:
        blobs["blobs/sha256/" + config["digest"].split(":")[1]] = b"{}"
    with tarfile.open(path, "w") as archive:
        for name, raw in blobs.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return index["digest"], config["digest"]


def test_oci_index_and_config_are_distinct_identities(tmp_path):
    path = tmp_path / "image.tar"
    index, config = oci_archive(path)
    result = archive_binding(path, index)
    assert result["index_digest"] != result["config_digest"]
    assert result["config_digest"] == config


@pytest.mark.parametrize("option", ["corrupt", "ambiguous"])
def test_oci_binding_rejects_corruption_and_ambiguous_platform(tmp_path, option):
    path = tmp_path / "image.tar"
    index, _ = oci_archive(path, **{option: True})
    with pytest.raises(ValueError):
        archive_binding(path, index)

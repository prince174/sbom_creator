import os

import pytest
from python_p1_boundary import MANIFEST_BYTES, classify, load_manifest, within_budget
from test_python_direct_p1 import fixture


@pytest.mark.parametrize("raw", [b"[project]\nname='a'\nname='b'", b"\xff", b"x=" + b"[" * 2000])
def test_invalid_no_input_echo(tmp_path, raw):
    (tmp_path / "pyproject.toml").write_bytes(raw)
    result = load_manifest(tmp_path)
    assert result["status"] == "UNKNOWN"
    assert "document" not in result


def test_regular_hash_and_missing(tmp_path):
    assert load_manifest(tmp_path)["status"] == "not-applicable"
    (tmp_path / "pyproject.toml").write_text("[project]\nname='app'", encoding="utf-8")
    assert load_manifest(tmp_path)["document"]["project"]["name"] == "app"
    assert len(load_manifest(tmp_path)["sha256"]) == 64


def test_oversized_and_directory(tmp_path):
    path = tmp_path / "pyproject.toml"
    path.write_bytes(b"#" * (MANIFEST_BYTES + 1))
    assert load_manifest(tmp_path)["status"] == "UNKNOWN"
    path.unlink()
    path.mkdir()
    assert load_manifest(tmp_path)["status"] == "UNKNOWN"


def test_symlink(tmp_path):
    target = tmp_path / "outside"
    target.write_text("[project]\nname='app'")
    try:
        os.symlink(target, tmp_path / "pyproject.toml")
    except OSError:
        pytest.skip("Host cannot create symlink")
    assert load_manifest(tmp_path)["status"] == "UNKNOWN"


def test_total_budget_depth_cycle_and_keys():
    assert within_budget(["abc"], max_nodes=2, max_text=3)
    assert not within_budget(["abc"], max_text=2)
    assert not within_budget({"abcdef": 1}, max_text=5)
    assert not within_budget([1, 2], max_nodes=2)
    cyclic = []
    cyclic.append(cyclic)
    assert not within_budget(cyclic, max_depth=3)


def test_oversized_image_never_becomes_empty_success():
    source, image = fixture()
    image["ignored"] = "x" * (16 * 1024 * 1024)
    result = classify(source, image)
    assert result["status"] == "UNKNOWN"
    assert result["coverage"] is None
    assert not result["edges"]

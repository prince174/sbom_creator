import io
import tarfile

import pytest
from paired_jinja import verify_metadata


def fixture(path, version="3.0.4", duplicate=False):
    with tarfile.open(path, "w") as archive:
        values = [("jinja2", "Name: Jinja2\nVersion: 3.1.6\nRequires-Dist: MarkupSafe>=2.0\nRequires-Dist: Babel>=2.7; extra == 'i18n'\n"),
                  ("markupsafe", f"Name: MarkupSafe\nVersion: {version}\n")]
        if duplicate:
            values.append(("duplicate", "Name: MarkupSafe\nVersion: 2.0\n"))
        for name, text in values:
            raw = text.encode()
            member = tarfile.TarInfo(f"project/lib/python3.12/site-packages/{name}.dist-info/METADATA")
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return {"metadata": {"component": {"bom-ref": "root"}},
            "components": [{"bom-ref": "dep", "name": "MarkupSafe", "version": "3.0.4"}],
            "dependencies": [{"ref": "root", "dependsOn": ["dep"]}]}


def test_runtime_metadata_graph(tmp_path):
    archive = tmp_path / "app.tar"
    result = verify_metadata(archive, fixture(archive))
    assert result["direct"] == [{"name": "MarkupSafe", "version": "3.0.4"}]
    assert len(result["conditional_requires_dist"]) == 1


def test_reference_version_conflict(tmp_path):
    archive = tmp_path / "app.tar"
    bom = fixture(archive, version="3.0.3")
    with pytest.raises(ValueError, match="version mismatch"):
        verify_metadata(archive, bom)


def test_duplicate_installation(tmp_path):
    archive = tmp_path / "app.tar"
    bom = fixture(archive, duplicate=True)
    with pytest.raises(ValueError, match="Ambiguous"):
        verify_metadata(archive, bom)


def test_flat_inventory_is_not_root_graph(tmp_path):
    archive = tmp_path / "app.tar"
    bom = fixture(archive)
    bom["dependencies"] = []
    with pytest.raises(ValueError, match="root graph"):
        verify_metadata(archive, bom)

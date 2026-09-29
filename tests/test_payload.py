import io
import json
import tarfile
import zipfile

import pytest
from test_core import doc, package

from sbom_creator.core import artifact_identity, reconcile
from sbom_creator.payload import collect


def archive_fixture(tmp_path, contents, artifacts, missing=()):
    """A saved image with a known squashed inventory; missing files remain only in its layer."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as saved:
        for name, data in contents.items():
            info = tarfile.TarInfo(name.lstrip("/"))
            info.size = len(data)
            saved.addfile(info, io.BytesIO(data))
    target = tmp_path / "image.tar"
    metadata = {"manifest.json": json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode(),
                "config.json": json.dumps({"rootfs": {"diff_ids": ["sha256:fixture"]}}).encode(),
                "layer.tar": layer.getvalue()}
    with tarfile.open(target, "w") as saved:
        for name, data in metadata.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            saved.addfile(info, io.BytesIO(data))
    files = [{"id": str(i), "location": {"path": name, "layerID": "sha256:fixture"},
              "metadata": {"type": "RegularFile", "size": len(data)}}
             for i, (name, data) in enumerate(contents.items()) if name not in missing]
    return doc(*artifacts, files=files), target


@pytest.mark.parametrize("removed", [False, True])
def test_python_record_uses_final_files_not_stale_lower_layer(tmp_path, removed):
    base = "/lib/site-packages"
    code = base + "/example/__init__.py"
    image, archive = archive_fixture(tmp_path, {
        base + "/example-1.2.3.dist-info/METADATA": b"metadata",
        base + "/example-1.2.3.dist-info/RECORD": b"example/__init__.py,,\n",
        code: b"value = 1\n"}, [package("a", locations=[{"path": base + "/example-1.2.3.dist-info/METADATA"}])],
        missing=[code] if removed else [])
    payload = collect(image, archive)
    result = reconcile(doc(), image, payload_evidence=payload)
    assert result["decisions"][0]["decision"] == ("UNKNOWN" if removed else "INCLUDE")
    if removed:
        assert result["decisions"][0]["review_reason"] == "PAYLOAD_NOT_CONFIRMED"


def test_npm_manifest_cannot_borrow_code_from_nested_package(tmp_path):
    def npm(pid, root):
        return package(pid, type="npm", purl="pkg:npm/example@1.2.3", foundBy="javascript-package-cataloger",
                       locations=[{"path": root + "/package.json"}])
    image, archive = archive_fixture(tmp_path, {
        "/app/package.json": b"{}", "/app/child/package.json": b"{}", "/app/child/index.js": b"module.exports=1;"},
        [npm("outer", "/app"), npm("inner", "/app/child")])
    payload = collect(image, archive)
    result = reconcile(doc(), image, payload_evidence=payload)
    assert result["decisions"][0]["selected_image_artifact_ids"] == ["inner"]
    assert payload["outer"]["status"] == "unconfirmed"


def test_npm_data_only_package_has_payload_when_declared_entry_exists(tmp_path):
    artifact = package("a", type="npm", purl="pkg:npm/example@1.2.3",
                       foundBy="javascript-package-cataloger", locations=[{"path": "/app/package.json"}])
    image, archive = archive_fixture(tmp_path, {
        "/app/package.json": b'{"main":"index.json"}', "/app/index.json": b'["MIT"]'}, [artifact])
    evidence = collect(image, archive)
    assert evidence["a"]["path"] == "/app/index.json"
    assert reconcile(doc(), image, payload_evidence=evidence)["decisions"][0]["decision"] == "INCLUDE"


@pytest.mark.parametrize("with_class", [False, True])
def test_java_checks_archive_class_payload_not_only_pom(tmp_path, with_class):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as jar:
        jar.writestr("META-INF/maven/org.example/example/pom.properties", "version=1.2.3")
        if with_class:
            jar.writestr("Example.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
    image, archive = archive_fixture(tmp_path, {"/app/example.jar": data.getvalue()}, [package(
        "a", type="java-archive", purl="pkg:maven/org.example/example@1.2.3", foundBy="java-archive-cataloger",
        locations=[{"path": "/app/example.jar"}], metadata={"virtualPath": "/app/example.jar"})])
    assert collect(image, archive)["a"]["status"] == ("confirmed" if with_class else "unconfirmed")


def test_invalid_archive_is_uncertainty_not_inclusion(tmp_path):
    image, archive = archive_fixture(tmp_path, {"/app/example.jar": b"broken zip"}, [package(
        "a", type="java-archive", purl="pkg:maven/org.example/example@1.2.3", foundBy="java-archive-cataloger",
        locations=[{"path": "/app/example.jar"}])])
    evidence = collect(image, archive)["a"]
    assert evidence["status"] == "unconfirmed" and evidence["error_type"] == "BadZipFile"


@pytest.mark.parametrize("directory,confirmed", [("x86_64-linux", True), ("aarch64-linux-musl", True), ("unrelated", False)])
def test_ruby_default_native_extension_uses_declared_platform_path(tmp_path, directory, confirmed):
    manifest = "/usr/local/lib/ruby/gems/3.3.0/specifications/default/example-1.2.3.gemspec"
    target = f"/usr/local/lib/ruby/3.3.0/{directory}/io/example.so"
    artifact = package("a", type="gem", purl="pkg:gem/example@1.2.3", foundBy="ruby-installed-gemspec-cataloger",
                       locations=[{"path": manifest}], metadata={"files": ["io/example.so"]})
    image, archive = archive_fixture(tmp_path, {manifest: b"metadata", target: b"native payload"}, [artifact])
    evidence = collect(image, archive)["a"]
    assert (evidence["status"] == "confirmed") is confirmed
    assert evidence["path"] == (target if confirmed else None)


def test_go_stdlib_prefix_exception_is_narrow_and_keeps_original_version():
    valid = package("go", "stdlib", "go1.24.13", type="go-module", purl="pkg:golang/stdlib@1.24.13",
                    foundBy="go-module-binary-cataloger")
    assert artifact_identity(valid)["identity_valid"]
    selected = reconcile(doc(), doc(valid))["selected_syft"]["artifacts"][0]
    assert selected["version"] == "go1.24.13" and selected["purl"] == "pkg:golang/stdlib@1.24.13"
    for changes in ({"version": "go1.24.14"}, {"name": "other"}, {"foundBy": "go-module-file-cataloger"}):
        assert not artifact_identity({**valid, **changes})["identity_valid"]


def test_ci_reference_keeps_unknown_but_gets_correct_review_scope():
    source = doc(package("ci", "actions/checkout", "v4", type="github-action",
                         purl="pkg:github/actions/checkout@v4", foundBy="github-actions-usage-cataloger"))
    row = reconcile(source, doc())["decisions"][0]
    assert row["decision"] == "UNKNOWN" and row["review_reason"] == "CI_CONFIGURATION"

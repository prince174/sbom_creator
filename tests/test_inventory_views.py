import copy

import pytest
from test_core import doc, package
from test_pipeline import real_catalogs as real_catalogs  # noqa: PLC0414

from sbom_creator.core import rules_assessor
from sbom_creator.exporter import split_inventory, validate_inventory_views
from sbom_creator.pipeline import publish_catalogs
from sbom_creator.validation import validate_cyclonedx


def test_os_partition_is_disjoint_preserves_packages_and_filters_cross_scope_edges():
    artifacts = [package("app", "openssl"), package("os", "openssl", type="deb",
                 purl="pkg:deb/debian/openssl@1.2.3?arch=amd64&distro=debian-12")]
    selected = doc(*artifacts)
    full = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "container", "name": "fixture", "bom-ref": "root"}},
            "components": [{"type": "library", "name": a["name"], "version": a["version"],
                            "bom-ref": a["id"], "purl": a["purl"]} for a in artifacts],
            "dependencies": [{"ref": "root", "dependsOn": ["app", "os"]},
                             {"ref": "app", "dependsOn": ["os"]}, {"ref": "os", "dependsOn": ["app"]}]}
    before = copy.deepcopy(full)
    app, os = split_inventory(full, selected)
    assert [c["bom-ref"] for c in app["components"]] == ["app"]
    assert [c["bom-ref"] for c in os["components"]] == ["os"]
    assert app["serialNumber"] != os["serialNumber"]
    assert full == before
    for document in (app, os):
        validate_cyclonedx(document)
        assert document["dependencies"][1]["dependsOn"] == []
    validate_inventory_views(full, app, os, selected)
    os["components"] = []
    with pytest.raises(ValueError, match="Dangling CycloneDX dependency"):
        validate_inventory_views(full, app, os, selected)


def test_real_conversion_publishes_os_separately_and_preserves_full_inventory(real_catalogs, tmp_path):
    import json
    source, original, settings = real_catalogs
    image = copy.deepcopy(original)
    os_package = copy.deepcopy(image["artifacts"][0])
    os_package.update(id="os-package-fixture", name="libc6", version="2.36", type="deb",
                      purl="pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12",
                      foundBy="dpkg-db-cataloger", metadataType="dpkg-db-entry", metadata={})
    image["artifacts"].append(os_package)
    output = tmp_path / "split"
    summary = publish_catalogs(source, image, output, settings, rules_assessor)
    assert summary["final_count"] == 2
    assert summary["os_count"] == 1 and summary["full_count"] == 3
    assert summary["selected_count"] == 3 and summary["inventory_scope"] == "non-os-packages-v1"
    docs = {name: json.loads((output / name).read_bytes()) for name in (
        "final.cdx.json", "os.cdx.json", "full.cdx.json", "selected.syft.json")}
    validate_inventory_views(docs["full.cdx.json"], docs["final.cdx.json"], docs["os.cdx.json"], docs["selected.syft.json"])
    assert all(c["name"] != "libc6" for c in docs["final.cdx.json"]["components"])

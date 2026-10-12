"""Recheck R3 receipts, installed versions and B0 coverage without rescanning."""
import json
import tarfile

from audit_reference_pairing import coordinate
from paired_express import OUT, WORK, application_tree, archive_binding, sha
from run import ROOT

from sbom_creator.validation import validate_cyclonedx


def main():
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    for name, field in (("sbom.json", "reference_sha256"), ("package-lock.json", "package_lock_sha256"),
                        ("package.json", "source_manifest_sha256"), ("Dockerfile", "recipe_sha256"),
                        ("application-tree.json", "application_tree_sha256")):
        if sha(OUT / name) != receipt[field]:
            raise ValueError("Reference receipt mismatch")
    for name, digest in receipt["outputs"].items():
        if sha(WORK / "analysis" / name) != digest:
            raise ValueError("Analyzer output receipt mismatch")
    tree = application_tree(WORK / "runtime-app.tar")
    if tree != application_tree(WORK / "builder-app.tar") or tree != json.loads((OUT / "application-tree.json").read_bytes()):
        raise ValueError("Paired application trees changed")
    for name in ("final.cdx.json", "os.cdx.json", "full.cdx.json"):
        validate_cyclonedx(json.loads((WORK / "analysis" / name).read_bytes()))
    binding = archive_binding(WORK / "runtime-image.tar", receipt["runtime_image"])
    if any(receipt["archive_binding"][k] != v for k, v in binding.items()):
        raise ValueError("Archive binding changed")
    bom = json.loads((OUT / "sbom.json").read_bytes())
    package = json.loads((OUT / "package.json").read_bytes())
    lock = json.loads((OUT / "package-lock.json").read_bytes())
    components = {c["bom-ref"]: c for c in bom["components"]}
    root = bom["metadata"]["component"]["bom-ref"]
    direct = [components[key] for key in next(d["dependsOn"] for d in bom["dependencies"] if d["ref"] == root)]
    if {c["name"] for c in direct} != set(package["dependencies"]):
        raise ValueError("Root declaration mismatch")
    with tarfile.open(WORK / "runtime-app.tar") as archive:
        for component in direct:
            name = component["name"]
            installed = json.load(archive.extractfile(f"app/node_modules/{name}/package.json"))
            if not (component["version"] == installed["version"] == lock["packages"]["node_modules/" + name]["version"]):
                raise ValueError("Reference, installed package and lockfile versions differ")
    final = json.loads((WORK / "analysis/final.cdx.json").read_bytes())
    observed = {coordinate(c.get("purl")) for c in final["components"]}
    covered = sum(coordinate(c["purl"]) in observed for c in direct)
    report = {"experiment": "R3", "reference_receipt_sha256": sha(OUT / "receipt.json"),
              "paired_runtime_verified": True, "declarations_lock_installed_versions_agree": True,
              "direct_reference_edges": len(direct), "reference_coordinates_in_final_inventory": covered,
              "final_components": len(final["components"]), "final_dependency_entries": len(final.get("dependencies", [])),
              "unknown_decisions": receipt["summary"]["decisions"]["UNKNOWN"], "three_sbom_schemas_validated": True,
              "direct_precision": None, "direct_recall": None, "direct_f1": None,
              "reason": "Inventory coordinate coverage is not a prediction of direct edges",
              "control_partition": "benchmarks/direct-evaluation-split-v1.json", "holdout_used_for_tuning": False}
    (ROOT / "docs/paired-express-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

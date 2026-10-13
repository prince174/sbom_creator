"""Recheck saved Python reference without rebuilding or giving it to the service."""
import json
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from paired_express import application_tree, archive_binding, sha
from paired_jinja import OUT, WORK, verify_metadata
from run import ROOT

from sbom_creator.validation import validate_cyclonedx


def main():
    receipt = json.loads((OUT / "receipt.json").read_bytes())
    for name, digest in receipt["reference_hashes"].items():
        if sha(OUT / name) != digest:
            raise ValueError("Reference changed")
    for name, digest in receipt["outputs"].items():
        if sha(WORK / "analysis" / name) != digest:
            raise ValueError("Analysis changed")
    if sha(WORK / "src/pyproject.toml") != sha(OUT / "pyproject.toml"):
        raise ValueError("Source differs from receipt")
    tree = application_tree(WORK / "runtime-app.tar")
    if tree != application_tree(WORK / "build-app.tar") or tree != json.loads((OUT / "application-tree.json").read_bytes()):
        raise ValueError("Venv tree changed")
    binding = archive_binding(WORK / "image.tar", receipt["image_binding"]["index_digest"])
    if binding != receipt["image_binding"]:
        raise ValueError("Image binding changed")
    bom = json.loads((OUT / "sbom.json").read_bytes())
    validate_cyclonedx(bom)
    metadata = verify_metadata(WORK / "runtime-app.tar", bom)
    root_version = bom["metadata"]["component"].get("version")
    if root_version is not None and root_version != metadata["root_version"]:
        raise ValueError("Root version mismatch")
    source = tomllib.loads((OUT / "pyproject.toml").read_text("utf-8"))
    declared = {canonicalize_name(r.name): r for r in map(Requirement, source["project"]["dependencies"])}
    if set(declared) != {canonicalize_name(c["name"]) for c in metadata["direct"]}:
        raise ValueError("Source declarations disagree")
    for component in metadata["direct"]:
        requirement = declared[canonicalize_name(component["name"])]
        if requirement.marker or requirement.extras or not requirement.specifier.contains(component["version"]):
            raise ValueError("Unsupported or inconsistent source requirement")
    for name in ("final", "os", "full"):
        validate_cyclonedx(json.loads((WORK / "analysis" / (name + ".cdx.json")).read_bytes()))
    report = {"experiment": "R11", "receipt_sha256": sha(OUT / "receipt.json"),
              "paired_image_verified": True, "direct_source_installed_reference_agree": True,
              "reference_root_version": root_version,
              "root_version_validation": "unknown in reference" if root_version is None else "matched",
              "metadata": metadata, "three_schemas_valid": True, "summary": receipt["summary"],
              "direct_precision": None, "direct_recall": None, "reason": "Python direct classifier absent",
              "holdout_used": False}
    (ROOT / "docs/paired-jinja-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

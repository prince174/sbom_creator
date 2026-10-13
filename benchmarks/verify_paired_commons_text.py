"""Recheck saved Python reference without rebuilding or giving it to the service."""
import json

from paired_commons_text import OUT, WORK, verify_metadata
from paired_express import application_tree, archive_binding, sha
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
    if sha(WORK / "src/pom.xml") != sha(OUT / "pom.xml"):
        raise ValueError("Source differs from receipt")
    tree = application_tree(WORK / "runtime-app.tar")
    if tree != application_tree(WORK / "build-app.tar") or tree != json.loads((OUT / "application-tree.json").read_bytes()):
        raise ValueError("Venv tree changed")
    binding = archive_binding(WORK / "image.tar", receipt["image_binding"]["index_digest"])
    if binding != receipt["image_binding"]:
        raise ValueError("Image binding changed")
    bom = json.loads((OUT / "sbom.json").read_bytes())
    validate_cyclonedx(bom)
    metadata = verify_metadata(WORK / "runtime-app.tar", bom,
                               json.loads((OUT / "dependency-tree.json").read_bytes()),
                               (OUT / "effective-pom.xml").read_bytes())
    tools = bom["metadata"]["tools"]
    if "2.9.3" not in json.dumps(tools):
        raise ValueError("Unexpected CycloneDX generator")
    for name in ("final", "os", "full"):
        validate_cyclonedx(json.loads((WORK / "analysis" / (name + ".cdx.json")).read_bytes()))
    report = {"experiment": "R21", "receipt_sha256": sha(OUT / "receipt.json"),
              "paired_image_verified": True, "effective_pom_installed_reference_agree": True,
              "reference_root_version": bom["metadata"]["component"]["version"],
              "root_version_validation": "matched",
              "metadata": metadata, "three_schemas_valid": True, "summary": receipt["summary"],
              "direct_precision": None, "direct_recall": None, "reason": "Java direct classifier absent",
              "holdout_used": False}
    (ROOT / "docs/paired-commons-text-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

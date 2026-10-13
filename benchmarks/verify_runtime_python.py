"""Replay six immutable paired catalogs through the integrated publication path."""
import argparse
import json
import re

from evaluate_python_control import evaluate
from paired_express import sha
from python_p1_projection import classify as frozen
from run import ROOT

from sbom_creator.acquire import Settings
from sbom_creator.core import rules_assessor
from sbom_creator.direct_evidence import load_manifest
from sbom_creator.pipeline import publish_catalogs
from sbom_creator.python_inputs import load_manifest as load_python_manifest
from sbom_creator.python_projection import classify
from sbom_creator.validation import validate_cyclonedx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="v1")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9-]{1,30}", args.run_id):
        raise ValueError("Invalid run ID")
    rows = []
    for pair in ("jinja-v1", "flask-v1", "packaging-v1", "httpx-v1"):
        work = ROOT / "benchmarks/.work" / ("paired-" + pair)
        old = work / "analysis"
        receipt = json.loads((ROOT / "benchmarks/references" / ("paired-" + pair) / "receipt.json").read_bytes())
        for name, digest in receipt["outputs"].items():
            if sha(old / name) != digest:
                raise ValueError("Frozen evidence changed")
        manifest = load_python_manifest(work / "src")
        if manifest["sha256"] != receipt["reference_hashes"]["pyproject.toml"]:
            raise ValueError("Source changed")
        source = json.loads((old / "source.syft.json").read_bytes())
        image = json.loads((old / "image.syft.json").read_bytes())
        if classify(manifest["document"], image) != frozen(manifest["document"], image):
            raise ValueError("Integrated classifier differs from frozen H2")
        output = ROOT / "benchmarks/.work" / ("runtime-python-" + args.run_id) / pair
        publish_catalogs(source, image, output, Settings(syft_binary=str(ROOT / ".tools/syft/syft.exe")),
                         rules_assessor, json.loads((old / "provenance.json").read_bytes()), load_manifest(work / "src"), manifest)
        report = json.loads((output / "direct-dependencies.json").read_bytes())
        predicted = frozen(manifest["document"], image)
        if [(e["name"], e["status"], e["version"]) for e in report["edges"]] != [(e["name"], e["status"], e["version"]) for e in predicted["edges"]]:
            raise ValueError("Export lost direct evidence")
        counts = {}
        for name in ("final", "os", "full"):
            filename = name + ".cdx.json"
            before = json.loads((old / filename).read_bytes())
            after = json.loads((output / filename).read_bytes())
            validate_cyclonedx(after)
            if {c["bom-ref"] for c in before["components"]} != {c["bom-ref"] for c in after["components"]}:
                raise ValueError("Inventory changed")
            edges = {d["ref"]: set(d.get("dependsOn", [])) for d in after.get("dependencies", [])}
            for edge in before.get("dependencies", []):
                if not set(edge.get("dependsOn", [])) <= edges.get(edge["ref"], set()):
                    raise ValueError("Existing graph lost edges")
            if name != "os":
                for edge in report["edges"]:
                    if edge["status"] == "DIRECT" and edge["component_ref"] not in edges.get(edge["owner_ref"], set()):
                        raise ValueError("Direct edge missing in CycloneDX")
            counts[name] = len(after["components"])
        row = {"pair": pair, "direct": report["direct_count"], "unknown": report["unknown_count"],
                     "inventory_unchanged": True, "counts": counts, "schemas_valid": True,
                     "direct_report_sha256": sha(output / "direct-dependencies.json")}
        if pair != "jinja-v1":
            control = evaluate(pair.removesuffix("-v1"))
            row["control"] = {k: control[k] for k in ("tp", "fp", "fn", "precision", "recall", "declaration_coverage")}
        rows.append(row)
        print(json.dumps(rows[-1]), flush=True)
    (ROOT / "docs/runtime-python-r19.json").write_text(json.dumps({"experiment": "R19", "rows": rows}, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

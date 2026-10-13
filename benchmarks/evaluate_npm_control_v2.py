"""Evaluate frozen H2 against H1 on preregistered control v2."""
import base64
import hashlib
import json
import tarfile
import time

from npm_direct_h1 import classify as baseline
from npm_direct_h2 import classify
from paired_express import application_tree, archive_binding, root_dependencies, sha
from run import ROOT

from sbom_creator.validation import validate_cyclonedx

FROZEN = "22996eb470e445efed77a78fde7880616b0dc657cef24f4f8d6821f7583af03e"


def main():
    if sha(ROOT / "benchmarks/npm_direct_h1.py") != FROZEN:
        raise ValueError("Holdout classifier changed")
    frozen = json.loads((ROOT / "docs/npm-h2-regression-v1.json").read_bytes())["hashes"]
    if any(sha(ROOT / "benchmarks" / n) != d for n, d in frozen.items()):
        raise ValueError("Frozen control or classifier changed")
    protocol = json.loads((ROOT / "benchmarks/npm-control-v2.json").read_bytes())
    rows = []
    for project, run_id in (("koa", "v1"), ("fastify", "v1"), ("hapi", "v3")):
        key = "paired-" + project + "-" + run_id
        work = ROOT / "benchmarks/.work" / key
        out = ROOT / "benchmarks/references" / key
        receipt = json.loads((out / "receipt.json").read_bytes())
        entry = next(p for p in protocol["repositories"] if p["id"] == project)
        if receipt["commit"] != entry["commit"] or receipt["repository_url"] != entry["url"]:
            raise ValueError("Build does not match preregistration")
        for name, digest in receipt["outputs"].items():
            if sha(work / "analysis" / name) != digest:
                raise ValueError("Output evidence changed")
        for name, field in (("sbom.json", "reference_sha256"), ("package-lock.json", "package_lock_sha256"),
                            ("package.json", "source_manifest_sha256"), ("Dockerfile", "recipe_sha256")):
            if sha(out / name) != receipt[field]:
                raise ValueError("Reference evidence changed")
        source = work / "src/package.json"
        if sha(source) != receipt["source_manifest_sha256"]:
            raise ValueError("Source changed")
        tree = application_tree(work / "runtime-app.tar")
        if (application_tree(work / "builder-app.tar") != tree
                or sha(out / "application-tree.json") != receipt["application_tree_sha256"]
                or tree != json.loads((out / "application-tree.json").read_bytes())):
            raise ValueError("Runtime differs from reference environment")
        binding = archive_binding(work / "runtime-image.tar", receipt["runtime_image"])
        if any(receipt["archive_binding"][k] != v for k, v in binding.items()):
            raise ValueError("Image archive changed")
        image = json.loads((work / "analysis/image.syft.json").read_bytes())
        raw_config = base64.b64decode(image["source"]["metadata"]["config"], validate=True)
        if "sha256:" + hashlib.sha256(raw_config).hexdigest() != binding["config_digest"]:
            raise ValueError("Syft scanned a different image")
        for name in ("final", "os", "full"):
            validate_cyclonedx(json.loads((work / "analysis" / (name + ".cdx.json")).read_bytes()))
        start = time.perf_counter()
        prediction = classify(json.loads(source.read_bytes()), image)
        elapsed = time.perf_counter() - start
        baseline_prediction = baseline(json.loads(source.read_bytes()), image)
        bom = json.loads((out / "sbom.json").read_bytes())
        validate_cyclonedx(bom)
        components = {c["bom-ref"]: c for c in bom.get("components", [])}
        refs = root_dependencies(bom)
        expected = {((components[r].get("group", "") + "/" if components[r].get("group") else "") + components[r]["name"], components[r]["version"]) for r in refs}
        package = json.loads(source.read_bytes())
        if {n for n, v in expected} != set(package.get("dependencies", {})):
            raise ValueError("Reference direct declarations disagree")
        lock = json.loads((out / "package-lock.json").read_bytes())
        with tarfile.open(work / "runtime-app.tar") as archive:
            for name, version in expected:
                installed = json.load(archive.extractfile(f"app/node_modules/{name}/package.json"))
                if installed["version"] != version or lock["packages"]["node_modules/" + name]["version"] != version:
                    raise ValueError("Installed/reference/lock versions disagree")
        actual = {(e["name"], e["version"]) for e in prediction["edges"] if e["status"] == "DIRECT"}
        tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
        old = {(e["name"], e["version"]) for e in baseline_prediction["edges"] if e["status"] == "DIRECT"}
        old_tp, old_fp, old_fn = len(old & expected), len(old - expected), len(expected - old)
        rows.append({"project": project, "commit": receipt["commit"], "reference_receipt_sha256": sha(out / "receipt.json"),
                     "tp": tp, "fp": fp, "fn": fn, "reference_edges": len(expected),
                     "baseline": {"tp": old_tp, "fp": old_fp, "fn": old_fn, "prediction": baseline_prediction},
                     "precision": tp / (tp + fp) if tp + fp else None,
                     "recall": tp / (tp + fn) if tp + fn else None,
                     "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
                     "unknown": sum(e["status"] == "UNKNOWN" for e in prediction["edges"]),
                     "coverage": len(actual) / len(expected) if expected else None,
                     "prediction_seconds": elapsed, "peak_rss": None, "prediction": prediction,
                     "three_sbom_schemas_valid": True})
    report = {"experiment": "R8", "classifier_hashes": frozen, "partition": "preregistered control v2",
              "production_changed": False, "rows": rows}
    (ROOT / "docs/npm-h2-control-v2.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

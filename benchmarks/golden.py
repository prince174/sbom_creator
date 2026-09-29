"""Controlled filesystem inventory with labels written before real Syft scans.

Requires Docker and pinned Syft. Builds a scratch image containing only generated
package payloads/metadata and copied locks; never starts it. This is a small
Python/npm inventory experiment, not ecosystem-wide accuracy or runtime usage.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbom_creator.acquire import Settings, clean_environment, run_command
from sbom_creator.pipeline import analyze_local, sha256, write_json


def create_fixture(root: Path) -> dict:
    source, image = root / "source", root / "rootfs"
    source.mkdir(parents=True)
    image.mkdir()
    requirements = "kept-python==1.0.0\nchanged-python==1.0.0\ndev-only-python==9.0.0\nlock-only-python==3.0.0\n"
    (source / "requirements.txt").write_text(requirements, encoding="utf-8")
    for prefix, name, version in (
        ("usr/lib", "kept-python", "1.0.0"), ("opt/venv/lib", "kept-python", "1.0.0"),
        ("usr/lib", "changed-python", "2.0.0"), ("usr/lib", "image-only-python", "4.0.0"),
    ):
        site = image / prefix / "python3.12/site-packages"
        metadata = site / f"{name.replace('-', '_')}-{version}.dist-info"
        metadata.mkdir(parents=True)
        (metadata / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
        module = site / name.replace("-", "_")
        module.mkdir()
        (module / "__init__.py").write_text(f"__version__ = '{version}'\n", encoding="utf-8")
        (metadata / "RECORD").write_text(f"{module.name}/__init__.py,,\n", encoding="utf-8")
    app = image / "app"
    app.mkdir()
    (app / "requirements.txt").write_text("kept-python==1.0.0\nlock-only-python==3.0.0\n", encoding="utf-8")
    lock = {"name": "fixture", "lockfileVersion": 3, "packages": {
        "node_modules/kept-js": {"version": "1.0.0"},
        "node_modules/lock-only-js": {"version": "9.0.0"},
        "node_modules/dev-only-js": {"version": "7.0.0", "dev": True},
    }}
    write_json(source / "package-lock.json", lock)
    write_json(app / "package-lock.json", lock)
    for folder, version in (("node_modules/kept-js", "1.0.0"),
                            ("nested/node_modules/kept-js", "2.0.0")):
        package = app / folder
        package.mkdir(parents=True)
        write_json(package / "package.json", {"name": "kept-js", "version": version})
        (package / "index.js").write_text(f"module.exports = '{version}';\n", encoding="utf-8")
    labels = {
        "scope": "Generated Python/npm payload inventory; not installation-tool, code reachability or production accuracy",
        "positive": ["pkg:pypi/kept-python@1.0.0", "pkg:pypi/changed-python@2.0.0",
                     "pkg:pypi/image-only-python@4.0.0", "pkg:npm/kept-js@1.0.0", "pkg:npm/kept-js@2.0.0"],
        "negative": ["pkg:pypi/dev-only-python@9.0.0", "pkg:pypi/lock-only-python@3.0.0",
                     "pkg:pypi/changed-python@1.0.0", "pkg:npm/lock-only-js@9.0.0", "pkg:npm/dev-only-js@7.0.0"],
        "scenarios": ["source-only", "copied locks", "installed plus same-identity declaration",
                      "source/image version conflict", "two delivered versions", "image-only", "two installed locations"],
    }
    write_json(root / "ground-truth.json", labels)
    (root / "Dockerfile").write_text("FROM scratch\nCOPY rootfs/ /\n", encoding="utf-8")
    (root / ".dockerignore").write_text("*\n!rootfs/\n!rootfs/**\n!Dockerfile\n", encoding="utf-8")
    return labels


def run(root: Path, syft: str, report: Path) -> dict:
    if root.exists() or report.exists():
        raise FileExistsError("Choose new work and report paths to preserve evidence")
    labels = create_fixture(root)
    label_hash = sha256(root / "ground-truth.json")
    settings = Settings(syft_binary=syft, pull_image=False, registry_hosts=("docker.io",))
    reference = "docker.io/sbom-creator-golden:" + label_hash[:12]
    run_command(["docker", "build", "--network=none", "-t", reference, str(root)],
                cwd=root, env=clean_environment(), timeout=120,
                max_output_bytes=settings.max_output_bytes, label="Golden scratch build")
    summary = analyze_local(root / "source", reference, root / "result", settings)
    result = root / "result"
    final = json.loads((result / "final.cdx.json").read_bytes())
    selected = json.loads((result / "selected.syft.json").read_bytes())
    decisions = json.loads((result / "decisions.json").read_bytes())
    observed = {a["purl"] for a in final["components"]}
    positive, negative = set(labels["positive"]), set(labels["negative"])
    candidates = {a["identity"] for a in decisions}
    assert positive <= candidates, "A delivered positive control was not observed by Syft"
    false_positive = sorted(observed - positive)
    false_negative = sorted(positive - observed)
    declaration_records = [a for a in selected["artifacts"] if a["foundBy"] in {
        "python-package-cataloger", "javascript-lock-cataloger"}]
    assert sha256(root / "ground-truth.json") == label_hash
    payload = {
        "passed": not false_positive and not false_negative and not declaration_records,
        "scope": labels["scope"], "scenarios": labels["scenarios"], "mode": summary["assessment_mode"],
        "ground_truth_written_before_scan": True, "ground_truth_sha256": label_hash,
        "positive_labels": len(positive), "negative_labels": len(negative),
        "true_positives": len(positive & observed), "false_positives": false_positive,
        "false_negatives": false_negative,
        "labelled_controls_observed": len((positive | negative) & candidates),
        "labels_not_observed_by_scanner": sorted((positive | negative) - candidates),
        "selected_declaration_records": len(declaration_records),
        "summary": summary, "analysis_directory": str(result),
        "image": json.loads((result / "provenance.json").read_bytes())["image"],
        "artifacts_sha256": {p.name: sha256(p) for p in result.iterdir()},
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, payload)
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--syft", required=True)
    args = parser.parse_args()
    result = run(args.work.resolve(), args.syft, args.report.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)

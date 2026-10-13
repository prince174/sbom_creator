"""Development-only declaration readiness, not a direct-dependency classifier."""
import hashlib
import json
import subprocess
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from run import ROOT


def declarations(document):
    project = document.get("project")
    if not isinstance(project, dict):
        return {"status": "UNKNOWN", "reason": "backend_metadata", "names": None}
    if "dependencies" in project.get("dynamic", []):
        return {"status": "UNKNOWN", "reason": "dynamic_dependencies", "names": None}
    values = project.get("dependencies", [])
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        return {"status": "UNKNOWN", "reason": "invalid_dependencies", "names": None}
    parsed = [Requirement(value) for value in values]
    return {"status": "static-declarations", "reason": "not_installed_or_build_usage_proof",
            "names": sorted({canonicalize_name(r.name) for r in parsed}),
            "conditional_count": sum(r.marker is not None for r in parsed),
            "extras_count": sum(bool(r.extras) for r in parsed),
            "url_count": sum(r.url is not None for r in parsed),
            "optional_groups": len(project.get("optional-dependencies", {})),
            "build_requirements_count": len(document.get("build-system", {}).get("requires", []))}


def main():
    split = json.loads((ROOT / "benchmarks/direct-evaluation-split-v1.json").read_bytes())
    index = json.loads((ROOT / "benchmarks/references/build-v1/index.json").read_bytes())
    rows = []
    for item in index["projects"]:
        if item["language"] != "Python" or item["id"] not in split["development"]:
            continue
        repo = ROOT / "benchmarks/.work" / item["id"] / "src"
        listing = subprocess.check_output(["git", "ls-tree", "--name-only", item["commit"], "--", "pyproject.toml"], cwd=repo, text=True)
        if listing.strip():
            raw = subprocess.check_output(["git", "show", item["commit"] + ":pyproject.toml"], cwd=repo)
            result = declarations(tomllib.loads(raw.decode("utf-8")))
            digest = hashlib.sha256(raw).hexdigest()
        else:
            result = {"status": "UNKNOWN", "reason": "no_pyproject_at_commit", "names": None}
            digest = None
        reference = ROOT / item["sbom"]
        bom = json.loads(reference.read_bytes())
        root = bom["metadata"]["component"]["bom-ref"]
        components = {c["bom-ref"]: c for c in bom.get("components", [])}
        entries = [e for e in bom.get("dependencies", []) if e["ref"] == root]
        names = sorted({canonicalize_name(components[r]["name"]) for r in entries[0].get("dependsOn", [])}) if len(entries) == 1 else None
        rows.append({"id": item["id"], "commit": item["commit"], "source_manifest_sha256": digest,
                     "declarations": result, "reference_names": names,
                     "reference_sha256": hashlib.sha256(reference.read_bytes()).hexdigest(),
                     "same_name_set": result["names"] == names if result["names"] is not None and names is not None else None,
                     "image_pair_verified": False})
    report = {"experiment": "R10", "scope": "Python development declaration audit only",
              "holdout_source_or_reference_read": False, "precision": None, "recall": None,
              "runtime_changed": False, "rows": rows}
    (ROOT / "docs/python-declarations-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

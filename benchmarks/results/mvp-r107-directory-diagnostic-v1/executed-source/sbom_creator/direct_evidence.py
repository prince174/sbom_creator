"""Bounded manifest input and direct-edge publication, separate from inventory policy."""
import hashlib
import json
import stat
from pathlib import Path

from packageurl import PackageURL

from .npm_direct import NAME, classify, parse, paths

LIMIT = 1024 * 1024


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest key")
        result[key] = value
    return result


def load_manifest(checkout):
    """Never follow a repository symlink or read an unbounded/nonregular file."""
    root = Path(checkout).resolve()
    path = root / "package.json"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.resolve() != path or info.st_size > LIMIT:
            return {"status": "UNKNOWN", "reason": "unsafe_or_oversized_manifest"}
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            return {"status": "UNKNOWN", "reason": "unsafe_or_oversized_manifest"}
        package = json.loads(raw, object_pairs_hook=_object)
        if not isinstance(package, dict):
            raise TypeError("Invalid manifest")
        if not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str):
            raise TypeError("Missing project identity")
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            values = package.get(field, {})
            if not isinstance(values, dict) or len(values) > 5000:
                raise ValueError("Invalid declaration map")
            if any(not NAME.fullmatch(k) or len(k) > 214 or not isinstance(v, str)
                   for k, v in values.items()):
                raise ValueError("Invalid declaration")
        return {"status": "available", "sha256": hashlib.sha256(raw).hexdigest(), "package": package}
    except FileNotFoundError:
        return {"status": "not-applicable", "reason": "no_root_package_json"}
    except (OSError, ValueError, TypeError, RecursionError):
        return {"status": "UNKNOWN", "reason": "unreadable_or_invalid_manifest"}


def annotate(document, image, manifest=None):
    """Only add verified package-to-package edges; never remove inventory or edges."""
    manifest = manifest or {"status": "UNKNOWN", "reason": "source_manifest_unavailable"}
    report = {k: v for k, v in manifest.items() if k != "package"}
    report.update(profile="npm-root-production-H2.1", graph_complete=False, build_usage_proven=False)
    if manifest.get("status") != "available":
        report["edges"] = []
        return report
    package = manifest["package"]
    prediction = classify(package, image)
    report.update(prediction)
    by_id = {}
    for component in document.get("components", []):
        ref = component["bom-ref"]
        aid = PackageURL.from_string(ref).qualifiers.get("package-id") if ref.startswith("pkg:") else ref
        by_id[aid] = component
    roots = [a for a in image.get("artifacts", []) if a.get("type") == "npm"
             and a.get("name") == package["name"] and a.get("version") == package["version"]
             and prediction["root_image_manifest"] in paths(a)]
    owner = by_id.get(roots[0].get("id")) if len(roots) == 1 else None
    targets = []
    for edge in report["edges"]:
        spec = edge["spec"]
        if parse(spec.removeprefix("^").removeprefix("~")) is None:
            edge["spec"] = "<unsupported>"  # Do not publish credentials from URL/git specs.
        if edge["status"] != "DIRECT":
            continue
        component = by_id.get(edge["artifact_id"])
        if owner is None or component is None:
            edge.update(status="UNKNOWN", reason="selected_inventory_identity_unavailable")
            continue
        ref = component["bom-ref"]
        edge.update(owner_ref=owner["bom-ref"], component_ref=ref)
        targets.append(ref)
        component.setdefault("properties", []).extend([
            {"name": "sbom-creator:direct-owner", "value": owner["bom-ref"]},
            {"name": "sbom-creator:direct-scope", "value": "runtime-declaration"},
        ])
    if targets:
        graph = document.setdefault("dependencies", [])
        node = next((e for e in graph if e["ref"] == owner["bom-ref"]), None)
        if node is None:
            node = {"ref": owner["bom-ref"], "dependsOn": []}
            graph.append(node)
        node["dependsOn"] = sorted(set(node.get("dependsOn", [])) | set(targets))
    report["direct_count"] = sum(e["status"] == "DIRECT" for e in report["edges"])
    report["unknown_count"] = sum(e["status"] == "UNKNOWN" for e in report["edges"])
    return report

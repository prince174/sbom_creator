"""Experimental H2.1; H1.1 classification rules with the R6 range matcher.

Not imported by production. Frozen baseline stays unchanged for comparisons.
"""
from npm_direct_h1 import NAME, paths
from npm_range_h2 import satisfies

VERSION = "H2.1"


def classify(package, image):
    artifacts = [a for a in image.get("artifacts", []) if a.get("type") == "npm"]
    roots = {(a.get("id"), p) for a in artifacts
             if package.get("name") and package.get("version")
             and a.get("name") == package["name"] and a.get("version") == package["version"]
             for p in paths(a) if p.endswith("/package.json") and "/node_modules/" not in p}
    root_path = next(iter(roots))[1] if len(roots) == 1 else None
    declarations = dict(package.get("dependencies", {}))
    # Optional dependencies override dependencies in npm; retain explicit unknowns.
    declarations.update(package.get("optionalDependencies", {}))
    rows = []
    for name, spec in sorted(declarations.items()):
        row = {"owner": "package.json", "name": name, "spec": spec,
               "scope": "optional" if name in package.get("optionalDependencies", {}) else "runtime",
               "status": "UNKNOWN", "version": None}
        if package.get("workspaces") or package.get("overrides"):
            reason = "unsupported_workspace_or_override"
        elif row["scope"] == "optional" or name in package.get("peerDependencies", {}):
            reason = "unsupported_optional_or_peer"
        elif not NAME.fullmatch(name) or any(p in (".", "..") for p in name.split("/")):
            reason = "unsupported_name"
        elif not root_path:
            reason = "missing_or_ambiguous_root"
        else:
            target = root_path.removesuffix("package.json") + "node_modules/" + name + "/package.json"
            candidates = [a for a in artifacts if target in paths(a)]
            if len(candidates) != 1 or candidates[0].get("name") != name:
                reason = "missing_or_ambiguous_installation"
            else:
                artifact = candidates[0]
                match = satisfies(artifact.get("version"), spec)
                reason = "unsupported_version_range" if match is None else "version_conflict"
                if match:
                    row.update(status="DIRECT", version=artifact["version"],
                               image_path=target, artifact_id=artifact.get("id"))
                    reason = "root_declaration_and_local_installation"
        rows.append(dict(row, reason=reason))
    return {"classifier": VERSION, "root_image_manifest": root_path, "edges": rows,
            "excluded_scopes": ["devDependencies", "peer-only"],
            "build_usage_proven": False}

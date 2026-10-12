"""Experimental H1.1: root production declarations + image package locations.

Pure data classifier: no build execution, reference, filesystem or network access.
Not wired into the service. Supports only exact stable x.y.z and ~x.y.z.
"""
import re

VERSION = "H1.1"
STABLE = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
NAME = re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+\Z")


def satisfies(version, spec):
    """Return None for unsupported syntax, never approximate npm semver."""
    if not isinstance(spec, str) or not isinstance(version, str):
        return None
    actual = re.fullmatch(STABLE, version)
    expected = re.fullmatch(r"(~?)" + STABLE, spec)
    if not actual or not expected:
        return None
    a = tuple(map(int, actual.groups()))
    b = tuple(map(int, expected.groups()[1:]))
    return a == b if not expected[1] else a[:2] == b[:2] and a[2] >= b[2]


def paths(artifact):
    result = set()
    for location in artifact.get("locations", []):
        path = location.get("path", "")
        access = location.get("accessPath", path)
        if (isinstance(path, str) and path.startswith("/") and "\\" not in path
                and all(part not in ("", ".", "..") for part in path.split("/")[1:])
                and access == path):
            result.add(path)
    return result


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

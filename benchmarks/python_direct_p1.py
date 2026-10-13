"""Experimental P1: static unconditional declarations + same-environment METADATA.

Pure data; no project execution, host marker evaluation, oracle or file access.
"""
from pathlib import PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


def installations(artifact):
    found = set()
    for location in artifact.get("locations", []):
        path = location.get("path", "")
        if (not path.startswith("/") or "\\" in path or location.get("accessPath", path) != path
                or any(p in (".", "..", "") for p in path.split("/")[1:])):
            continue
        parsed = PurePosixPath(path)
        if parsed.name == "METADATA" and parsed.parent.name.endswith(".dist-info") and parsed.parent.parent.name in ("site-packages", "dist-packages"):
            found.add(str(parsed.parent.parent))
    return found


def classify(document, image):
    project = document.get("project", {})
    report = {"classifier": "P1.0", "owner": "pyproject.toml", "edges": [],
              "status": "UNKNOWN", "build_usage_proven": False, "root_version_from_source": project.get("version"),
              "excluded_scopes": ["optional-dependencies", "build-system", "dependency-groups"]}
    if not project.get("name") or "dependencies" in project.get("dynamic", []):
        report["reason"] = "missing_project_or_dynamic_dependencies"
        return report
    try:
        declared = [Requirement(value) for value in project.get("dependencies", [])]
    except (InvalidRequirement, TypeError):
        report["reason"] = "invalid_declarations"
        return report
    artifacts = [a for a in image.get("artifacts", []) if a.get("type") == "python"
                 and a.get("metadataType") == "python-package"]
    roots = [(a, env) for a in artifacts if canonicalize_name(a["name"]) == canonicalize_name(project["name"])
             for env in installations(a)]
    root, environment = roots[0] if len(roots) == 1 else (None, None)
    installed_requirements = []
    if root:
        try:
            installed_requirements = [Requirement(v) for v in root.get("metadata", {}).get("requiresDist", [])]
            if project.get("version") and Version(project["version"]) != Version(root["version"]):
                root = None
        except (InvalidRequirement, InvalidVersion):
            root = None
    report.update(status="evaluated", installed_root_version=root["version"] if root else None,
                  root_identity_basis="unique installed name and corroborated declaration; commit binding not proven")
    for req in declared:
        name = canonicalize_name(req.name)
        edge = {"name": name, "owner": "pyproject.toml", "status": "UNKNOWN", "version": None}
        if req.marker is not None or req.extras or req.url:
            reason = "conditional_extras_or_url_not_supported"
        elif not root:
            reason = "missing_ambiguous_or_conflicting_root"
        else:
            corroborating = [r for r in installed_requirements if canonicalize_name(r.name) == name]
            matches = [a for a in artifacts if canonicalize_name(a["name"]) == name and environment in installations(a)]
            if len(corroborating) != 1 or corroborating[0].marker or corroborating[0].extras or corroborating[0].url or corroborating[0].specifier != req.specifier:
                reason = "installed_declaration_not_corroborated"
            elif len(matches) != 1:
                reason = "missing_or_ambiguous_installation"
            else:
                target = matches[0]
                try:
                    version = Version(target["version"])
                    compatible = not version.is_prerelease and req.specifier.contains(version)
                except InvalidVersion:
                    compatible = False
                reason = "version_conflict_or_unsupported"
                if compatible:
                    edge.update(status="DIRECT", version=target["version"], artifact_id=target["id"],
                                owner_artifact_id=root["id"], environment=environment)
                    reason = "source_and_installed_declaration_same_environment"
        report["edges"].append(dict(edge, reason=reason))
    return report

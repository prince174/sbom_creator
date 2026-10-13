"""Experimental GAV/owner corroboration only; never proves scope or directness."""


def gav(artifact):
    if artifact.get("type") != "java-archive":
        return None
    metadata = artifact.get("metadata", {})
    records = [metadata[k] for k in ("pomProperties", "pomProject") if metadata.get(k)]
    values = set()
    for record in records:
        if record.get("version") and record["version"] != artifact.get("version"):
            return None
        version = record.get("version") or artifact.get("version")
        value = (record.get("groupId"), record.get("artifactId"), version)
        if all(isinstance(v, str) and v and "${" not in v and v != "UNKNOWN" for v in value):
            values.add(value)
    return next(iter(values)) if len(values) == 1 else None


def module_location(artifact, path):
    locations = artifact.get("locations", [])
    # Syft directory paths are rooted at the scan directory, including Windows.
    def normalize(value):
        return value.replace("\\", "/").lstrip("/")
    return len(locations) == 1 and all(
        normalize(locations[0].get(key, "")) == path for key in ("path", "accessPath")
    )


def match(source, image, owner, dependency, module):
    def unknown(reason):
        return {"status": "UNKNOWN", "reason": reason, "direct_edge_proven": False}
    for catalog in (source, image):
        ids = [a.get("id") for a in catalog["artifacts"]]
        if any(not isinstance(i, str) or not i for i in ids) or len(ids) != len(set(ids)):
            return unknown("ambiguous_artifact_ids")
    matches = []
    for catalog, coordinate, source_side in ((source, owner, True), (source, dependency, True),
                                              (image, owner, False), (image, dependency, False)):
        candidates = [a for a in catalog["artifacts"] if gav(a) == coordinate
                      and (not source_side or module_location(a, module))]
        if len(candidates) != 1:
            return unknown("missing_or_ambiguous_gav_owner")
        matches.append(candidates[0]["id"])
    src_owner, src_dep, image_owner, image_dep = matches
    if src_owner == src_dep or image_owner == image_dep:
        return unknown("self_edge")
    edges = [e for e in source.get("artifactRelationships", [])
             if e.get("type") == "dependency-of" and e.get("parent") == src_dep and e.get("child") == src_owner]
    if len(edges) != 1:
        return unknown("missing_or_ambiguous_source_edge")
    return {"status": "CORROBORATED_CANDIDATE", "source_owner": src_owner,
            "source_dependency": src_dep, "image_owner": image_owner, "image_dependency": image_dep,
            "owner_gav": owner, "dependency_gav": dependency, "module": module,
            "direct_edge_proven": False, "effective_scope": None, "build_usage_proven": False}

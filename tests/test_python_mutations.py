from test_python_direct import fixture


def cases():
    mutations = [
        ("valid", "none", None),
        ("project_array", "project", []),
        ("project_name_integer", "project.name", 42),
        ("dynamic_integer", "project.dynamic", 42),
        ("dependency_integer", "project.dependencies", [42]),
        ("dependencies_string", "project.dependencies", "dep>=2"),
        ("artifacts_null", "artifacts", None),
        ("artifact_null", "artifacts.0", None),
        ("metadata_null", "artifacts.0.metadata", None),
        ("requires_dist_null", "artifacts.0.metadata.requiresDist", None),
        ("requires_dist_integer", "artifacts.0.metadata.requiresDist", [42]),
        ("locations_null", "artifacts.1.locations", None),
        ("location_null", "artifacts.1.locations.0", None),
        ("path_null", "artifacts.1.locations.0.path", None),
        ("version_null", "artifacts.1.version", None),
        ("id_null", "artifacts.1.id", None),
        ("duplicate_id", "artifacts.1.id", "app"),
    ]
    for name, path, value in mutations:
        source, image = fixture()
        if path != "none":
            parts = path.split(".")
            target = source if parts[0] == "project" else image
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            key = int(parts[-1]) if isinstance(target, list) else parts[-1]
            target[key] = value
        yield name, source, image


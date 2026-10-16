"""Shape validation for P1 input."""
from .python_direct import classify as frozen_classify


def text(value, limit=8192):
    return isinstance(value, str) and 0 < len(value) <= limit and "\x00" not in value


def strings(value, limit=5000):
    return isinstance(value, list) and len(value) <= limit and all(text(v) for v in value)


def valid(source, image):
    if not isinstance(source, dict) or not isinstance(image, dict):
        return False
    project = source.get("project", {})
    if not isinstance(project, dict):
        return False
    if not text(project.get("name"), 512):
        return False
    if "version" in project and not text(project["version"], 512):
        return False
    if not strings(project.get("dynamic", [])) or not strings(project.get("dependencies", [])):
        return False
    artifacts = image.get("artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) > 100000:
        return False
    ids = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            return False
        identity = artifact.get("id")
        if not text(identity, 512) or identity in ids:
            return False
        ids.add(identity)
        if artifact.get("type") != "python" or artifact.get("metadataType") != "python-package":
            continue
        if not text(artifact.get("name"), 512) or not text(artifact.get("version"), 512):
            return False
        metadata = artifact.get("metadata", {})
        if not isinstance(metadata, dict) or not strings(metadata.get("requiresDist", [])):
            return False
        locations = artifact.get("locations", [])
        if not isinstance(locations, list) or len(locations) > 10000:
            return False
        for location in locations:
            if not isinstance(location, dict) or not text(location.get("path")):
                return False
            if "accessPath" in location and not text(location["accessPath"]):
                return False
    return True


def classify(source, image):
    if not valid(source, image):
        return {"classifier": "P1.0+experimental-guard", "status": "UNKNOWN", "edges": [],
                "reason": "invalid_or_over_limit_input", "build_usage_proven": False,
                "coverage": None}
    return frozen_classify(source, image)

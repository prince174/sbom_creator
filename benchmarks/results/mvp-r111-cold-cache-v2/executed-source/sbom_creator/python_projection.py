"""Bounded projection; preserve every candidate and ID ambiguity."""
from .python_guard import classify as guarded
from .python_inputs import MAX_DEPTH, MAX_NODES, MAX_TEXT, unknown


class Budget:
    def __init__(self):
        self.nodes = MAX_NODES
        self.text = MAX_TEXT

    def charge(self, value):
        stack = [(value, 0)]
        while stack:
            item, depth = stack.pop()
            self.nodes -= 1
            if self.nodes < 0 or depth > MAX_DEPTH:
                raise ValueError("budget")
            if isinstance(item, str):
                self.text -= len(item)
            elif isinstance(item, dict):
                if 2 * len(item) + len(stack) > self.nodes:
                    raise ValueError("budget")
                for key, child in item.items():
                    stack.extend(((key, depth + 1), (child, depth + 1)))
            elif isinstance(item, list):
                if len(item) + len(stack) > self.nodes:
                    raise ValueError("budget")
                stack.extend((child, depth + 1) for child in item)
            if self.text < 0:
                raise ValueError("budget")


def project_inputs(source, image):
    if not isinstance(source, dict) or not isinstance(image, dict):
        raise TypeError("shape")
    project = source.get("project", {})
    if not isinstance(project, dict):
        raise TypeError("shape")
    selected = {"project": {k: project[k] for k in ("name", "version", "dynamic", "dependencies") if k in project}}
    budget = Budget()
    budget.charge(selected)
    artifacts = image.get("artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) > 100000:
        raise TypeError("shape")
    projected = []
    budget.charge({"artifacts": []})
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise TypeError("shape")
        value = {k: artifact[k] for k in ("id", "type", "metadataType") if k in artifact}
        if artifact.get("type") == "python" and artifact.get("metadataType") == "python-package":
            value.update({k: artifact[k] for k in ("name", "version") if k in artifact})
            metadata = artifact.get("metadata", {})
            locations = artifact.get("locations", [])
            if not isinstance(metadata, dict) or not isinstance(locations, list) or len(locations) > 10000:
                raise TypeError("shape")
            value["metadata"] = {k: metadata[k] for k in ("requiresDist",) if k in metadata}
            value["locations"] = []
            for location in locations:
                if not isinstance(location, dict):
                    raise TypeError("shape")
                value["locations"].append({k: location[k] for k in ("path", "accessPath") if k in location})
        budget.charge(value)
        projected.append(value)
    return selected, {"artifacts": projected}


def classify(source, image):
    try:
        selected, projected = project_inputs(source, image)
    except (ValueError, TypeError):
        return unknown("invalid_or_over_budget_projection")
    return guarded(selected, projected)

"""Facts about source-model/image agreement; disagreement is not an error label."""
from .java_resolver import coordinate


def index(document):
    pending = list(document.get('components', []))
    root = document.get('metadata', {}).get('component')
    if root:
        pending.append(root)
    identities = set()
    while pending:
        component = pending.pop()
        identity = coordinate(component)
        if identity:
            identities.add(identity)
        pending.extend(component.get('components', []))
    return identities


def compare(build, image):
    left, right = index(build), index(image)
    return {'status': 'compared', 'scope': 'Maven component identities and exact versions',
            'original_build_reproduced': False, 'precision': None, 'recall': None,
            'interpretation': 'Agreement facts only; build-only/optional/test/packaging differences require scope evidence',
            'shared': sorted(left & right), 'build_model_only': sorted(left-right),
            'image_only': sorted(right-left), 'build_count': len(left), 'image_count': len(right)}

"""Normalize Trivy POM wrapper graphs by source path, never by PURL alone."""
from collections import Counter

from compare_java_js import all_components, coord


def extract(document):
    components = all_components(document)
    references = [component['bom-ref'] for component in components]
    if len(references) != len(set(references)):
        raise ValueError('Duplicate component references')
    by_ref = {component['bom-ref']: component for component in components}
    dependencies = document.get('dependencies', [])
    dependency_ids = [dependency['ref'] for dependency in dependencies]
    if len(dependency_ids) != len(set(dependency_ids)):
        raise ValueError('Duplicate graph references')
    graph = {dependency['ref']: dependency.get('dependsOn', []) for dependency in dependencies}
    wrappers = [component for component in components if component.get('type') == 'application'
                and {'name': 'aquasecurity:trivy:Type', 'value': 'pom'} in component.get('properties', [])]
    counts = Counter(component.get('name') for component in wrappers)
    rows = []
    for wrapper in wrappers:
        row = {'path': wrapper.get('name'), 'status': 'UNKNOWN', 'owner': None, 'direct': [], 'unknown_targets': 0}
        children = graph.get(wrapper['bom-ref'], [])
        if counts[row['path']] != 1 or len(children) != 1 or children[0] not in by_ref:
            rows.append(row)
            continue
        owner_ref = children[0]
        owner = coord(by_ref[owner_ref])
        if owner is None or not owner.startswith('pkg:maven/') or owner_ref not in graph:
            rows.append(row)
            continue
        values = [coord(by_ref[ref]) if ref in by_ref else None for ref in graph[owner_ref]]
        row.update(owner=owner, direct=sorted({value for value in values if value}),
                   unknown_targets=sum(value is None for value in values),
                   status='CANDIDATE' if all(values) or not values else 'PARTIAL_UNKNOWN')
        rows.append(row)
    return rows

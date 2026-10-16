"""Publish Java source edges, separately from image inventory and build usage."""
from collections import defaultdict

from .java_resolver import coordinate


def annotate(document, report):
    """Only connect already selected, unique package instances in the final graph."""
    by_purl = defaultdict(list)
    for component in document.get('components', []):
        purl = coordinate(component)
        if purl:
            by_purl[purl].append(component)
    for edge in report.get('edges', []):
        edge['inventory_binding'] = 'UNKNOWN'
        if edge['status'] != 'DIRECT':
            continue
        owners, targets = by_purl[edge['owner']], by_purl[edge['component']]
        if len(owners) != 1 or len(targets) != 1:
            continue
        owner, target = owners[0], targets[0]
        edge.update(inventory_binding='unique-selected-identities', owner_ref=owner['bom-ref'],
                    component_ref=target['bom-ref'])
        target.setdefault('properties', []).extend([
            {'name': 'sbom-creator:direct-owner', 'value': owner['bom-ref']},
            {'name': 'sbom-creator:direct-owner-module', 'value': edge['owner_module']},
            {'name': 'sbom-creator:direct-scope', 'value': 'unprofiled-source-declaration'},
        ])
        graph = document.setdefault('dependencies', [])
        node = next((d for d in graph if d['ref'] == owner['bom-ref']), None)
        if node is None:
            node = {'ref': owner['bom-ref'], 'dependsOn': []}
            graph.append(node)
        node['dependsOn'] = sorted(set(node.get('dependsOn', [])) | {target['bom-ref']})
    return report

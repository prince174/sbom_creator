"""Read native source edges; explicit-scope filtering is an experimental adapter."""
from java_gav_evidence import module_location


def extract(catalog, module):
    artifacts = catalog['artifacts']
    ids = [a.get('id') for a in artifacts]
    if len(ids) != len(set(ids)) or any(not i for i in ids):
        return {'status': 'UNKNOWN', 'rows': [], 'reason': 'ambiguous_ids'}
    owners = [a for a in artifacts if a.get('metadata', {}).get('pomProject')
              and a.get('foundBy') == 'java-pom-cataloger' and module_location(a, module)]
    if len(owners) != 1:
        return {'status': 'UNKNOWN', 'rows': [], 'reason': 'ambiguous_owner'}
    by_id = {a['id']: a for a in artifacts}
    rows = []
    for edge in catalog.get('artifactRelationships', []):
        if edge.get('type') != 'dependency-of' or edge.get('child') != owners[0]['id']:
            continue
        dep = by_id.get(edge.get('parent'))
        if dep is None:
            return {'status': 'UNKNOWN', 'rows': [], 'reason': 'dangling_edge'}
        props = dep.get('metadata', {}).get('pomProperties', {})
        rows.append({'coordinate': [props.get('groupId'), props.get('artifactId'), dep.get('version')],
                     'raw_scope': props.get('scope'),
                     'retained_by_explicit_scope_filter': props.get('scope') not in ('test', 'provided', 'system'),
                     'effective_scope': None})
    return {'status': 'EXTRACTED', 'owner_id': owners[0]['id'], 'rows': rows}

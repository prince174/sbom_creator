"""Narrow Go declaration/binary candidates, not build-import proof."""
import re


def declarations(raw):
    if len(raw) > 1024 * 1024:
        raise ValueError('manifest_budget')
    module = None
    rows = []
    block = False
    for line in raw.decode('utf-8').splitlines():
        code, _, comment = line.partition('//')
        code = code.strip()
        if not code:
            continue
        if code.startswith('module ') and not module and not block:
            module = code[7:].strip()
        elif re.fullmatch(r'go \d+\.\d+(?:\.\d+)?', code) and not block:
            continue
        elif code == 'require (' and not block:
            block = True
        elif code == ')' and block:
            block = False
        else:
            entry = code if block else code.removeprefix('require ') if code.startswith('require ') else ''
            match = re.fullmatch(r'([^\s"()]+) (v[^\s"()]+)', entry)
            if not match:
                raise ValueError('unsupported_go_mod_syntax')
            if comment.strip() not in ('', 'indirect'):
                raise ValueError('unsupported_requirement_comment')
            rows.append({'name': match[1], 'version': match[2], 'indirect': comment.strip() == 'indirect'})
    if not module or block or len({r['name'] for r in rows}) != len(rows):
        raise ValueError('ambiguous_manifest')
    return module, rows


def predict(raw, image, commit):
    try:
        module, rows = declarations(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return {'status': 'UNKNOWN', 'reason': str(exc), 'candidates': [], 'unknown_count': None}
    artifacts = image['artifacts']
    ids = [a['id'] for a in artifacts]
    if len(ids) != len(set(ids)):
        return {'status': 'UNKNOWN', 'reason': 'duplicate_ids', 'candidates': [], 'unknown_count': None}
    owners = [a for a in artifacts if a.get('name') == module and a.get('type') == 'go-module'
              and a.get('metadataType') == 'go-module-buildinfo-entry' and a.get('metadata', {}).get('goBuildSettings')]
    if len(owners) != 1:
        return {'status': 'UNKNOWN', 'reason': 'ambiguous_owner', 'candidates': [], 'unknown_count': None}
    owner = owners[0]
    if owner['metadata'].get('mainModule') != module:
        return {'status': 'UNKNOWN', 'reason': 'owner_module_mismatch', 'candidates': [], 'unknown_count': None}
    settings = owner['metadata']['goBuildSettings']
    values = {s['key']: s['value'] for s in settings}
    if len(values) != len(settings) or values.get('vcs.revision') != commit or values.get('vcs.modified') != 'false':
        return {'status': 'UNKNOWN', 'reason': 'unconfirmed_commit', 'candidates': [], 'unknown_count': None}
    locations = owner.get('locations', [])
    if len(locations) != 1 or locations[0].get('path') != locations[0].get('accessPath'):
        return {'status': 'UNKNOWN', 'reason': 'ambiguous_binary', 'candidates': [], 'unknown_count': None}
    binary = locations[0]['path']
    candidates = []
    unknown = 0
    for row in rows:
        if row['indirect']:
            continue
        matches = [a for a in artifacts if a.get('name') == row['name'] and a.get('version') == row['version']
                   and a.get('metadataType') == 'go-module-buildinfo-entry'
                   and a.get('metadata', {}).get('mainModule') == module
                   and len(a.get('locations', [])) == 1
                   and a['locations'][0].get('path') == binary and a['locations'][0].get('accessPath') == binary]
        if len(matches) != 1:
            unknown += 1
        else:
            candidates.append({'owner_id': owner['id'], 'dependency_id': matches[0]['id'], **row,
                               'status': 'DECLARED_BINARY_CANDIDATE', 'direct_edge_proven': False})
    return {'status': 'EXPERIMENTAL_CANDIDATES', 'candidates': candidates, 'unknown_count': unknown,
            'excluded_indirect': sum(r['indirect'] for r in rows),
            'limitation': 'Import graph/build tags/scopes unknown; go.mod indirect flag alone is not build directness proof'}

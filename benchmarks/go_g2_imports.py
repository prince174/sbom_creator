"""Experimental reachable root-module imports; no code execution."""


def traverse(module, entry_directory, index, installed):
    packages = index['packages']
    if entry_directory not in packages or packages[entry_directory]['name'] != 'main':
        return {'status': 'UNKNOWN', 'reason': 'entry_not_main', 'modules': []}
    visited = set()
    queue = [entry_directory]
    external = set()
    while queue:
        directory = queue.pop()
        if directory in visited:
            continue
        visited.add(directory)
        if directory not in packages:
            return {'status': 'UNKNOWN', 'reason': 'missing_local_package', 'modules': []}
        for imported in packages[directory]['imports']:
            if imported == module or imported.startswith(module + '/'):
                target = '.' if imported == module else imported[len(module) + 1:]
                if '..' in target.split('/'):
                    return {'status': 'UNKNOWN', 'reason': 'invalid_local_import', 'modules': []}
                queue.append(target)
                continue
            candidates = [path for path in installed if imported == path or imported.startswith(path + '/')]
            if candidates:
                longest = max(candidates, key=len)
                external.add((longest, installed[longest]))
            elif '.' in imported.split('/')[0] or imported.startswith('.'):
                return {'status': 'UNKNOWN', 'reason': 'unmapped_external_import', 'modules': []}
    return {'status': 'STATIC_IMPORT_CANDIDATES', 'modules': sorted(external),
            'visited_source_packages': sorted(visited), 'direct_edge_proven': False,
            'limitation': 'Standard imports assumed by path shape; limited build context and single module'}

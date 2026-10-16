"""Normalize cdxgen module ownership, retaining source and original-build limits."""
from pathlib import Path, PurePosixPath

from .java_inputs import NS, parse, value
from .java_resolver import coordinate


def module_path(component, checkout):
    paths = [p.get('value') for p in component.get('properties', []) if p.get('name') == 'internal:SrcFile']
    if len(paths) != 1 or not isinstance(paths[0], str):
        return None
    name = paths[0].removeprefix('/tmp/').removeprefix('project/')
    path = PurePosixPath(name)
    if path.is_absolute() or '\\' in name or ':' in name or '..' in path.parts or path.name != 'pom.xml':
        return None
    full = Path(checkout)/name
    if full.is_symlink() or not full.is_file() or not full.resolve().is_relative_to(Path(checkout).resolve()):
        return None
    return name


def extract(document, checkout):
    root = document.get('metadata', {}).get('component', {})
    owners, pending = [], [root]
    while pending:
        c = pending.pop()
        owners.append(c)
        pending.extend(c.get('components', []))
        if len(owners) > 4096:
            raise ValueError('Module owner budget')
    by_ref = {}
    pending = [*document.get('components', []), *owners]
    while pending:
        c = pending.pop()
        ref = c.get('bom-ref')
        if ref in by_ref and coordinate(by_ref[ref]) != coordinate(c):
            raise ValueError('Conflicting build component reference')
        by_ref[ref] = c
        pending.extend(c.get('components', []))
        if len(by_ref) > 100_000:
            raise ValueError('Build graph budget')
    dependencies = document.get('dependencies', [])
    graph = {d['ref']: d.get('dependsOn', []) for d in dependencies}
    if len(graph) != len(dependencies):
        raise ValueError('Duplicate build graph node')
    paths = {c.get('bom-ref'): module_path(c, checkout) for c in owners}
    modules, edges, containment = [], [], []
    for c in owners:
        owner, path, ref = coordinate(c), paths[c.get('bom-ref')], c.get('bom-ref')
        module = {'owner': owner, 'owner_module': path, 'status': 'evaluated' if owner and path and ref in graph else 'UNKNOWN'}
        modules.append(module)
        if module['status'] == 'UNKNOWN':
            continue
        pom = parse((Path(checkout)/path).read_bytes())
        children = {(PurePosixPath(path).parent / (n.text or '').strip() / 'pom.xml').as_posix()
                    for n in pom.findall(NS+'modules/'+NS+'module')}
        declared = {(value(d, 'groupId'), value(d, 'artifactId'))
                    for d in pom.findall(NS+'dependencies/'+NS+'dependency')}
        for target_ref in graph[ref]:
            target = by_ref.get(target_ref, {})
            identity = coordinate(target)
            # cdxgen adds aggregator -> nested module edges. Source <modules>
            # proves containment; an explicit dependency on that same module is
            # retained. The original tool BOM is kept without rewriting it.
            if paths.get(target_ref) in children and (target.get('group'), target.get('name')) not in declared:
                containment.append({'owner_ref': ref, 'module_ref': target_ref, 'owner_module': path})
                continue
            edges.append({'owner': owner, 'owner_module': path, 'component': identity,
                'component_exact_purl': target.get('purl'), 'version': target.get('version'),
                'status': 'DIRECT' if identity else 'UNKNOWN', 'scope': 'compile+runtime-analysis-environment',
                'build_owner_ref': ref, 'build_component_ref': target_ref,
                'reason': 'native_build_tool_dependency_graph' if identity else 'unresolved_target',
                'original_build_activation': 'UNKNOWN', 'build_usage_proven': False,
                'evidence': {'resolver': 'cdxgen/13.4.0', 'owner_ref': ref, 'target_ref': target_ref}})
    return {'modules': modules, 'edges': edges, 'module_containment': containment,
            'direct_count': sum(e['status'] == 'DIRECT' for e in edges),
            'unknown_count': sum(e['status'] == 'UNKNOWN' for e in edges),
            'graph_complete': False, 'original_build_reproduced': False}

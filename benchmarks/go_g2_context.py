"""Experimental eligibility gate; never infer a dependency from eligibility."""
import re


def context(info, module, commit, *, workspace=False):
    def unknown(reason):
        return {'status': 'UNKNOWN', 'reason': reason}
    if workspace:
        return unknown('workspace')
    if not isinstance(info, dict) or not isinstance(module, str) or not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        return unknown('invalid_input')
    if not isinstance(info.get('Settings'), list) or not isinstance(info.get('Deps', []), (list, type(None))):
        return unknown('invalid_metadata_lists')
    settings = {}
    for row in info.get('Settings') or []:
        if not isinstance(row, dict) or not isinstance(row.get('Key'), str) or not isinstance(row.get('Value'), str):
            return unknown('invalid_settings')
        if row['Key'] in settings:
            return unknown('duplicate_settings')
        settings[row['Key']] = row['Value']
    required = {'vcs': 'git', 'vcs.revision': commit, 'vcs.modified': 'false',
                'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': 'amd64', 'GOAMD64': 'v1',
                '-buildmode': 'exe', '-compiler': 'gc'}
    if any(settings.get(key) != value for key, value in required.items()):
        return unknown('unsupported_build_context')
    if info.get('GoVersion') != 'go1.24.13':
        return unknown('unsupported_toolchain')
    if any(settings.get(key) for key in ('-tags', '-race', '-msan', '-asan', 'GOEXPERIMENT', '-gcflags', '-asmflags')):
        return unknown('unsupported_build_flags')
    main = info.get('Main')
    if not isinstance(main, dict) or main.get('Path') != module or main.get('Replace'):
        return unknown('module_owner')
    entry = info.get('Path')
    if not isinstance(entry, str) or not (entry == module or entry.startswith(module + '/')):
        return unknown('entry_outside_module')
    relative = '.' if entry == module else entry[len(module) + 1:]
    if relative != '.' and any(part in ('', '.', '..') for part in relative.split('/')):
        return unknown('invalid_entry_path')
    installed = {}
    for dep in info.get('Deps') or []:
        if not isinstance(dep, dict) or dep.get('Replace'):
            return unknown('unsupported_dependency')
        name, version = dep.get('Path'), dep.get('Version')
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version or name in installed:
            return unknown('ambiguous_dependency')
        installed[name] = version
    return {'status': 'ELIGIBLE_CANDIDATE', 'entry': relative, 'installed': installed,
            'direct_edge_proven': False}

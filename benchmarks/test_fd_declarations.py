from audit_fd_declarations import declarations


def test_owner_alias_scope_and_unresolved_versions():
    rows = declarations(b'''[package]
name="app"
[dependencies]
renamed={package="actual",version="1.2",optional=true}
[build-dependencies]
build="0.3"
[target.'cfg(windows)'.dev-dependencies]
test={workspace=true}
''')
    assert [(r['owner'], r['name'], r['scope'], r['target']) for r in rows] == [
        ('app', 'actual', 'normal', None), ('app', 'build', 'build', None),
        ('app', 'test', 'dev', 'cfg(windows)')]
    assert all(r['resolved_version'] is None and r['build_activation'] == 'UNKNOWN' for r in rows)
    assert rows[0]['version_requirement'] == '1.2'
    assert rows[0]['optional'] is True
    assert rows[2]['workspace_inherited'] is True

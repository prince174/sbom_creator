from go_g2_imports import traverse


def test_reachable_packages_exclude_other_main_and_transitive():
    packages = {'.': {'name': 'main', 'imports': ['example.com/app/local', 'fmt']},
                'local': {'name': 'local', 'imports': ['example.com/lib/sub']},
                'cmd/other': {'name': 'main', 'imports': ['example.com/transitive/sub']}}
    result = traverse('example.com/app', '.', {'packages': packages},
                      {'example.com/lib': 'v1', 'example.com/transitive': 'v2'})
    assert result['modules'] == [('example.com/lib', 'v1')]
    assert result['visited_source_packages'] == ['.', 'local']


def test_missing_local_or_external_unknown():
    for imported in ('example.com/app/missing', 'unknown.example/pkg'):
        result = traverse('example.com/app', '.', {'packages': {'.': {'name': 'main', 'imports': [imported]}}}, {})
        assert result['status'] == 'UNKNOWN'


def test_longest_module_path_and_cycles():
    index = {'packages': {'.': {'name': 'main', 'imports': ['example.com/app', 'example.com/lib/sub/package']}}}
    assert traverse('example.com/app', '.', index, {'example.com/lib': 'v1', 'example.com/lib/sub': 'v2'})['modules'] == [('example.com/lib/sub', 'v2')]

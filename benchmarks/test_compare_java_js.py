from compare_java_js import all_components, graph


def test_nested_components_are_not_missing_dependencies():
    child = {'bom-ref': 'child', 'purl': 'pkg:npm/dep@2'}
    document = {'components': [{'bom-ref': 'owner', 'purl': 'pkg:npm/app@1', 'components': [child]}],
                'dependencies': [{'ref': 'owner', 'dependsOn': ['child']}]}
    assert child in all_components(document)
    assert graph(document, 'pkg:npm/app@1') == {'pkg:npm/dep@2'}


def test_missing_owner_graph_unknown_not_empty():
    assert graph({'components': [], 'dependencies': []}, 'pkg:npm/app@1') is None


def test_trivy_lock_wrapper_and_exact_versions():
    bom = {'components': [{'bom-ref': 'lock', 'type': 'application', 'name': 'package-lock.json',
                           'properties': [{'name': 'aquasecurity:trivy:Type', 'value': 'npm'}]},
                          {'bom-ref': 'dep', 'purl': 'pkg:npm/%40scope/dep@2'}],
           'dependencies': [{'ref': 'lock', 'dependsOn': ['dep']}]}
    assert graph(bom, 'pkg:npm/app@1', npm_lock_wrapper=True) == {'pkg:npm/@scope/dep@2'}
    assert graph(bom, 'pkg:npm/app@1') is None

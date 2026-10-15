from compare_java_js import graph


def test_missing_owner_graph_unknown_not_empty():
    assert graph({'components': [], 'dependencies': []}, 'pkg:npm/app@1') is None


def test_trivy_lock_wrapper_and_exact_versions():
    bom = {'components': [{'bom-ref': 'lock', 'type': 'application', 'name': 'package-lock.json',
                           'properties': [{'name': 'aquasecurity:trivy:Type', 'value': 'npm'}]},
                          {'bom-ref': 'dep', 'purl': 'pkg:npm/%40scope/dep@2'}],
           'dependencies': [{'ref': 'lock', 'dependsOn': ['dep']}]}
    assert graph(bom, 'pkg:npm/app@1', npm_lock_wrapper=True) == {'pkg:npm/@scope/dep@2'}
    assert graph(bom, 'pkg:npm/app@1') is None

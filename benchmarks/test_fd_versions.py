from audit_fd_versions import associate


def test_version_presence_is_not_edge_proof_and_multiple_lock_versions_unknown():
    rows = [{'name': 'dep', 'workspace_inherited': False, 'scope': 'normal', 'build_activation': 'UNKNOWN'}]
    lock = {'package': [{'name': 'dep', 'version': '1.0', 'source': 'registry+https://github.com/rust-lang/crates.io-index'}]}
    image = {'artifacts': [{'name': 'dep', 'version': '1.0', 'type': 'rust-crate'}]}
    result = associate(rows, lock, image)[0]
    assert result['resolved_version'] == '1.0'
    assert result['direct_edge_proven'] is False
    assert result['build_activation'] == 'UNKNOWN'
    lock['package'].append(dict(lock['package'][0], version='2.0'))
    assert associate(rows, lock, image)[0]['status'] == 'UNKNOWN'

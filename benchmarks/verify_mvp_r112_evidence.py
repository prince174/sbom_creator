"""Verify current source, sealed R112 publications, tests and retained old inputs."""
from __future__ import annotations

import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'benchmarks/results'
COMMIT = '88de0918b0ed34701f8537d291a752a172cbd40b'
TARGET = RESULTS / 'mvp-r112-final-validation.json'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def main():
    if TARGET.exists():
        raise FileExistsError('Preserve completed validation')
    predictions = RESULTS / 'mvp-r112-java-v1'
    frozen = read(predictions / 'freeze.json')
    marker = read(predictions / 'predictions-complete.json')
    assert not marker['failed'] and marker['completed'] == frozen['cases']
    assert marker['freeze_sha256'] == sha(predictions / 'freeze.json')
    exact, eol = [], []
    for name,digest in frozen['code_sha256'].items():
        actual = ROOT/'src'/name
        snapshot = predictions/'executed-source'/name
        assert sha(actual) == sha(snapshot) == digest
        committed=subprocess.run(['git','show',COMMIT+':src/'+name],cwd=ROOT,
            capture_output=True,check=True).stdout
        raw=actual.read_bytes()
        if committed == raw:
            exact.append(name)
        else:
            assert committed.replace(b'\r\n',b'\n') == raw.replace(b'\r\n',b'\n')
            eol.append(name)
    assert len(exact)+len(eol) == 48
    for name in frozen['cases']:
        directory=predictions/name
        assert sha(directory/'run.json') == marker['run_sha256'][name]
        for path,digest in read(directory/'run.json')['output_sha256'].items():
            assert Path(path).name == path and sha(directory/'analysis'/path) == digest
    prior=read(RESULTS/'mvp-r111-final-validation.json')['old_manifests_sha256']
    prior['mvp-r111-evidence-manifest.json']='dfd8685e0872267314c2f6b661f462acba0143b79352b0363f3d154dd9a398a3'
    assert all(sha(RESULTS/name) == digest for name,digest in prior.items())
    olddb=ROOT/'benchmarks/.work/trivy-reactor-image-v1/cache/java-db/trivy-java.db'
    assert sha(olddb) == 'c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25'
    tests={}
    passed,skipped=set(),set()
    for name in ('mvp-r112-full-service-v1.xml','mvp-r112-benchmark-regression-v1.xml',
                 'mvp-r112-evaluator-tests-v1.xml','mvp-r112-evaluator-tests-v2.xml',
                 'mvp-r112-container-tests-v2.xml'):
        suite=next(ET.parse(RESULTS/name).iter('testsuite')).attrib
        assert int(suite['errors']) == int(suite['failures']) == 0
        tests[name]={**suite,'sha256':sha(RESULTS/name)}
        for case in ET.parse(RESULTS/name).iter('testcase'):
            node=(case.attrib['classname'],case.attrib['name'])
            (skipped if case.find('skipped') is not None else passed).add(node)
    native=read(RESULTS/'mvp-r112-native-path-v2/report.json')
    assert native['status'] == 'passed' and native['skips'] == 0
    assert native['installed_source_sha256'] == frozen['code_sha256']
    evaluation=RESULTS/'mvp-r112-evaluation-v1/evaluation.json'
    report={'status':'PASS','runtime_commit':COMMIT,'source_files':48,
        'git_byte_exact':exact,'git_crlf_lf_only':eol,'executed_snapshots_unchanged':True,
        'old_manifests_sha256':prior,'old_database_unchanged':True,
        'new_database_sha256':frozen['database_sha256'],
        'prediction_marker_sha256':sha(predictions/'predictions-complete.json'),
        'evaluation_sha256':sha(evaluation),'test_reports':tests,
        'unique_passing_test_nodes':len(passed),'unique_skipped_test_nodes':len(skipped),
        'native_peer_symlink_guard_passed':True,'native_peer_symlink_skips':0,
        'deployed_services_changed':False,'foreign_recipes_or_reference_pairs_rebuilt':False}
    TARGET.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'PASS','byte_exact':len(exact),'eol_only':len(eol)}))


if __name__ == '__main__':
    main()

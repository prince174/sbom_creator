"""Compare raw source scope adapter to immutable synthetic build scopes."""
import json
import xml.etree.ElementTree as ET

from java_local_parent import NS
from paired_express import sha
from run import ROOT, atomic_json, run_command
from syft_java_source_baseline import extract


def main():
    work = ROOT / 'benchmarks/.work/syft-scope-r32'
    refs = ROOT / 'benchmarks/references/maven-scope-fixture-v1'
    receipt = json.loads((refs / 'receipt.json').read_bytes())
    for name, digest in receipt['hashes'].items():
        if sha(refs / name) != digest:
            raise ValueError('Build evidence changed: ' + name)
    work.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in ('inherited', 'override', 'profile'):
        catalog_path = work / (case + '.syft.json')
        if not catalog_path.exists():
            run_command([str(ROOT / '.tools/syft/syft.exe'), 'scan', 'dir:' + str(refs / case / 'source'),
                         '-o', 'syft-json=' + str(catalog_path)], work / (case + '.log'))
        catalog = json.loads(catalog_path.read_bytes())
        if catalog['descriptor']['version'] != '1.51.1':
            raise ValueError('Unexpected Syft version')
        prediction = extract(catalog, 'child/pom.xml')
        # Build effective model is evaluation-only, read after extraction.
        root = ET.fromstring((refs / case / 'effective-pom.xml').read_bytes())
        deps = root.findall('m:dependencies/m:dependency', NS)
        if len(deps) != 1:
            raise ValueError('Unexpected reference')
        scope = deps[0].findtext('m:scope', 'compile', NS)
        retained = [r for r in prediction['rows'] if r['retained_by_explicit_scope_filter']]
        rows.append({'case': case, 'prediction': prediction, 'build_scope': scope,
                     'retained_candidate_rows': len(retained),
                     'non_runtime_scope_retained': scope not in ('compile', 'runtime') and bool(retained),
                     'catalog_sha256': sha(catalog_path)})
    report = {'experiment': 'R32', 'synthetic': True, 'syft_version': '1.51.1',
              'reference_receipt_sha256': sha(refs / 'receipt.json'), 'rows': rows,
              'runtime_changed': False, 'direct_precision': None, 'direct_recall': None,
              'limitation': 'Source-only scope counterexamples; not a representative accuracy sample'}
    atomic_json(ROOT / 'docs/syft-scope-counterexamples-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

"""Revalidate stored no-lock service finals; do not rerun or retune classifiers."""
import hashlib
import json
import subprocess

from compare_java_js import all_components, coord
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import projected, read, reference, versions
from run import ROOT, atomic_json

from sbom_creator.validation import validate_cyclonedx


def main():
    output = ROOT / 'benchmarks/results/runtime-accuracy-r102'
    if output.exists():
        raise FileExistsError('Preserve report')
    if subprocess.check_output(['git', 'diff', '4f29791', 'HEAD', '--', 'src'], cwd=ROOT):
        raise ValueError('Stored service baseline no longer matches runtime source')
    rows = []
    for namespace in ('no-lock-v1', 'no-lock-expanded-v1'):
        for report_path in sorted((ROOT / 'benchmarks/results' / namespace).glob('paired-*/report.json')):
            report = read(report_path)
            pair = report_path.parent.name
            work = ROOT / 'benchmarks/.work' / namespace / pair / 'analysis'
            final_path = work / 'final.cdx.json'
            final_hash = hashlib.sha256(final_path.read_bytes()).hexdigest()
            if report['direct'].get('result_sha256', final_hash) != final_hash:
                raise ValueError('Stored result hash differs')
            final = read(final_path)
            for view in ('final', 'os', 'full'):
                validate_cyclonedx(read(work / (view + '.cdx.json')))
            folder = ROOT / 'benchmarks/references' / pair
            receipt = read(folder / 'receipt.json')
            if 'reference_hashes' in receipt:
                reference(folder)
            elif hashlib.sha256((folder / 'sbom.json').read_bytes()).hexdigest() != receipt['reference_sha256']:
                raise ValueError('Immutable legacy reference hash differs')
            bom = read(folder / 'sbom.json')
            owner = coord(bom['metadata']['component'])
            actual = projected(final, '/app/', owner)
            expected = {coord(c) for c in all_components(bom) if coord(c)}-{owner}
            if len(actual & expected) != report['components']['tp']:
                raise ValueError('Final component projection differs')
            rows.append({'project': report['project'], 'components': report['components'],
                         'versions': versions(actual, expected), 'direct': report['direct'],
                         'final_sha256': final_hash, 'scope': '/app/',
                         'missing': sorted(expected-actual), 'extra': sorted(actual-expected)})
    components = aggregate([r['components'] for r in rows])
    direct = aggregate([r['direct'] for r in rows if r['direct']['status'] == 'MEASURED'])
    positive = [r['components'] for r in rows if r['components']['reference'] > 0]
    atomic_json(output / 'javascript.json', {'runtime_source_equal_to_baseline': '4f29791',
                'mode': 'no project source/image lockfiles', 'projects': len(rows),
                'positive_component_projects': len(positive), 'components_micro': components,
                'components_macro_positive_projects': {k: sum(r[k] for r in positive)/len(positive)
                for k in ('precision', 'recall', 'f1')}, 'direct_micro': direct,
                'owner_status_coverage': sum(r['direct']['status'] == 'MEASURED' for r in rows)/len(rows),
                'rows': rows, 'three_views_each_schema_valid': True,
                'limitations': ['Stored unmodified service output revalidated, not a fresh engine scan',
                               'Disclosed fixed /app fixtures; not independent general ownership acceptance',
                               'Four empty component projects excluded from positive macro; Axios remains weak',
                               'Component metrics compare exact names AND versions; platform/OS separate']})
    print(json.dumps({'components': components, 'direct': direct, 'projects': len(rows)}))


if __name__ == '__main__':
    main()

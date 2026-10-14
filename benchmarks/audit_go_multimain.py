"""Audit failed labeling/commit conditions; never declare this ground truth."""
import json

from go_multimain_counterexample import OUT, WORK
from paired_express import root_dependencies, sha
from run import ROOT, atomic_json
from verify_paired_hey import json_stream


def main():
    receipt = json.loads((OUT / 'receipt.json').read_bytes())
    for name, digest in receipt['reference_hashes'].items():
        if sha(OUT / name) != digest:
            raise ValueError('Reference changed')
    for name, digest in receipt['outputs'].items():
        if sha(WORK / 'analysis' / name) != digest:
            raise ValueError('Scan changed')
    packages = json_stream((OUT / 'packages.json').read_text())
    by_path = {p['ImportPath']: p for p in packages}
    native = set()
    for pkg in packages:
        if pkg.get('Module', {}).get('Main'):
            for imported in pkg.get('Imports', []):
                module = by_path[imported].get('Module', {})
                if module and not module.get('Main'):
                    native.add((module['Path'], module['Version']))
    bom = json.loads((OUT / 'sbom.json').read_bytes())
    refs = root_dependencies(bom)
    cdx = {(c['name'], c['version']) for c in bom['components'] if c['bom-ref'] in refs}
    info = (OUT / 'build-info.txt').read_text()
    dirty = 'vcs.modified=true' in info
    report = {'experiment': 'R38', 'native_main_import_modules': sorted(native), 'cyclonedx_root_edges': sorted(cdx),
              'label_agreement': native == cdx, 'binary_vcs_modified': dirty,
              'eligible_for_direct_accuracy': native == cdx and not dirty,
              'classifier_outcome': 'UNKNOWN/unconfirmed_commit', 'runtime_changed': False,
              'direct_precision': None, 'direct_recall': None,
              'reason': 'Module-root declarations and selected-main package imports differ; dirty binary build'}
    atomic_json(ROOT / 'docs/go-multimain-audit-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

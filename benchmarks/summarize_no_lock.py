"""Verify no-lock ablation bindings and aggregate saved per-project results."""
import base64
import hashlib
import json

from compare_java_js import coord, graph
from compare_no_lock import verify_variant
from paired_express import archive_binding
from run import ROOT, atomic_json


def main():
    out = ROOT / 'benchmarks/results/no-lock-v1'
    rows = []
    unknown_reference_edges = 0
    for path in sorted(out.glob('*/report.json')):
        row = json.loads(path.read_bytes())
        if row['direct']['status'] != 'MEASURED':
            reference = json.loads((ROOT / 'benchmarks/references' / path.parent.name / 'sbom.json').read_bytes())
            edges = graph(reference, coord(reference['metadata']['component']))
            if edges is None:
                raise ValueError('Unknown reference graph cannot enter aggregate accuracy')
            unknown_reference_edges += len(edges)
        work = ROOT / 'benchmarks/.work/no-lock-v1' / path.parent.name
        original = ROOT / 'benchmarks/.work' / path.parent.name
        binding = archive_binding(work / 'image.tar', row['derivative_image'])
        image = json.loads((work / 'analysis/image.syft.json').read_bytes())
        digest = 'sha256:' + hashlib.sha256(base64.b64decode(image['source']['metadata']['config'], validate=True)).hexdigest()
        if digest != binding['config_digest']:
            raise ValueError('Scanned derivative config differs')
        proof = verify_variant(original, work, row['derivative_image'], work / 'analysis')
        image_project = {coord(a) for a in image['artifacts'] if coord(a) and
                         any(p.get('path', '').startswith('/app/') for p in a.get('locations', []))}
        if image_project != set(proof['final_project_coordinates']):
            raise ValueError('Final project projection differs from scored inventory')
        proof.update(image_binding=binding, output_hashes={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (work / 'analysis').iterdir() if p.is_file()})
        atomic_json(path.parent / 'binding-proof.json', proof)
        rows.append(row)
    if len(rows) != 10:
        raise ValueError('All ten no-lock replays required')
    if unknown_reference_edges:
        raise ValueError('Known positive UNKNOWN edges must be counted as FN before aggregation')
    summary = {'rows': rows, 'projects': 10,
               'unknown_owner_reference_edges': unknown_reference_edges,
               'positive_component_roots': sum(r['components']['reference'] > 0 for r in rows),
               'owner_status_coverage': sum(r['direct']['status'] == 'MEASURED' for r in rows) / 10,
               'seconds': sum(r['seconds'] for r in rows), 'runtime_changed': False,
               'limitation': 'Disclosed fixtures, fixed /app projection, not independent general ownership validation.'}
    for field in ('components', 'direct'):
        measured = [r[field] for r in rows if field == 'components' or r[field]['status'] == 'MEASURED']
        total = {k: sum(r[k] for r in measured) for k in ('tp', 'fp', 'fn')}
        tp, fp, fn = (total[k] for k in ('tp', 'fp', 'fn'))
        total.update(precision=tp / (tp + fp) if tp + fp else None,
                     recall=tp / (tp + fn) if tp + fn else None,
                     f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None)
        reference_key = 'reference' if field == 'components' else 'reference_direct'
        positive = [r for r in measured if r[reference_key] > 0]
        for metric in ('precision', 'recall', 'f1'):
            total['macro_positive_' + metric] = sum(r[metric] for r in positive) / len(positive) if positive else None
        summary[field] = total
    atomic_json(out / 'summary.json', summary)
    print(json.dumps({k: v for k, v in summary.items() if k != 'rows'}))


if __name__ == '__main__':
    main()

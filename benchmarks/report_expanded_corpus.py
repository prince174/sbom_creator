"""Report expansion admission separately from the original fixed20 corpus."""
import hashlib
import json

from compare_java_js import all_components, coord, graph
from run import ROOT, atomic_json
from score_project_components import metrics

from sbom_creator.evaluation import compare
from sbom_creator.validation import validate_cyclonedx


def main():
    manifest=json.loads((ROOT/'benchmarks/java-js-expanded-v1.json').read_bytes())
    unchanged=all(hashlib.sha256((ROOT/f).read_bytes()).hexdigest()==digest for f,digest in manifest['candidate_freeze'].items())
    receipts={}
    for path in (ROOT/'benchmarks/references').glob('paired-*/receipt.json'):
        receipt=json.loads(path.read_bytes());receipts[receipt.get('project')]=(path,receipt)
    rows=[]
    for project in manifest['repositories']:
        row={'project':project['id'],'language':project['language'],'partition':project['partition'],
             'commit':project['commit'],'status':'PINNED_NOT_BUILT'}
        if project['id'] in receipts:
            path,receipt=receipts[project['id']]
            if receipt['commit']!=project['commit']:raise ValueError('Expansion revision differs')
            work=ROOT/'benchmarks/.work'/path.parent.name
            analysis=work/'analysis'
            if receipt.get('analysis_status', {}).get('status') == 'FAILED_OUTPUT_BUDGET':
                for relative, digest in receipt['reference_hashes'].items():
                    if hashlib.sha256((path.parent/relative).read_bytes()).hexdigest() != digest:
                        raise ValueError('Failed-analysis reference evidence changed')
                reference = json.loads((path.parent/'sbom.json').read_bytes())
                validate_cyclonedx(reference)
                labels = json.loads((path.parent/'module-labels.json').read_bytes())
                shipped = [label for label in labels if label['image_prefix']]
                for label in labels:
                    validate_cyclonedx(json.loads((path.parent/'modules'/label['path']/'sbom.json').read_bytes()))
                row.update(status='PAIRED', pair=path.parent.name,
                           analysis_status=receipt['analysis_status'],
                           reference_components=len(all_components(reference)),
                           reference_module_count=len(labels), shipped_module_count=len(shipped),
                           reference_module_direct_edges=sum(len(label['direct']) for label in labels),
                           known_shipped_module_direct_unmatched=sum(len(label['direct']) for label in shipped),
                           components=None, direct={'status': 'FAILED_ANALYSIS'},
                           component_metrics_status='FAILED_OUTPUT_BUDGET',
                           receipt_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           scope_note='Aggregate includes reactor artifacts; per-owner labels separate. Failed service output is not an empty successful prediction. All known shipped edges remain unmatched, not excluded from coverage.')
                rows.append(row)
                continue
            final=json.loads((analysis/'final.cdx.json').read_bytes())
            for view in ('final','os','full'):
                validate_cyclonedx(json.loads((analysis/(view+'.cdx.json')).read_bytes()))
            prefix='/app/' if project['language']=='JavaScript' else '/application/'
            predicted={coord(c) for c in all_components(final) if coord(c) and any(
                p.get('name','').startswith('syft:location:') and p.get('name','').endswith(':path')
                and p.get('value','').startswith(prefix) for p in c.get('properties',[]))}
            # First oracle access for scoring is after unchanged service output exists.
            reference=json.loads((path.parent/'sbom.json').read_bytes());validate_cyclonedx(reference)
            owner=coord(reference['metadata']['component']);predicted.discard(owner)
            expected={coord(c) for c in all_components(reference) if coord(c)}-{owner}
            direct=graph(reference,owner)
            root_ref=reference['metadata']['component']['bom-ref']
            adjacency={d['ref']:d.get('dependsOn',[]) for d in reference.get('dependencies',[])}
            depths={root_ref:0};pending=[root_ref]
            for node in pending:
                for target in adjacency.get(node,[]):
                    if target not in depths:
                        depths[target]=depths[node]+1;pending.append(target)
            row.update(status='PAIRED',pair=path.parent.name,reference_components=len(expected),
                       reference_max_shortest_hops=max(depths.values()),
                       reference_graph_edges=sum(len(v) for v in adjacency.values()),
                       reference_direct=len(direct) if direct is not None else None,
                       components=metrics(predicted,expected),direct=compare(analysis,reference,'runtime'),
                       missing=sorted(expected-predicted),extra=sorted(predicted-expected),
                       scoring_scope=prefix,receipt_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            row['known_reference_direct_fn'] = (len(direct) if direct is not None else None) if row['direct']['status'] != 'MEASURED' else row['direct']['fn']
            if receipt.get('runtime_kind') == 'spring-boot-jar':
                row['raw_build_reference_component_delta'] = row['components']
                row['components'] = None
                row['known_build_reference_unmatched_direct'] = row['known_reference_direct_fn']
                row['known_reference_direct_fn'] = None
                row.update(component_metrics_status='DIAGNOSTIC_BUILD_IMAGE_SCOPE_NOT_ADJUDICATED',
                           acceptance_component_metrics=None,
                           scope_note='Build-resolved starters/POMs/devtools and packaged payload can differ. Raw set delta is not automatically a runtime FP/FN verdict; budget and identity failures remain independently demonstrated.')
            if receipt.get('runtime_kind') == 'spring-boot-jar':
                label_reports = {
                    'java-spring-petclinic': 'boot-packaging-labels-v3',
                    'java-petclinic-rest': 'petclinic-rest-packaging-labels-v1',
                }
                label_name = label_reports.get(project['id'])
                label_path = ROOT/'benchmarks/results'/label_name/'report.json' if label_name else None
                if label_path is not None and label_path.exists():
                    labels = json.loads(label_path.read_bytes())
                    if labels['commit'] != receipt['commit'] or labels['unlabelled_build_reference']:
                        raise ValueError('Packaging label binding/coverage differs')
                    row['components'] = metrics(predicted, set(labels['packaged']))
                    row['component_metrics_status'] = 'KNOWN_PACKAGED_LABELS_WITH_ADDITIONAL_UNKNOWN'
                    row['packaged_reference_components'] = len(labels['packaged'])
                    row['packaged_unknown_artifacts'] = len(labels['unknown_packaged'])
                    row['packaging_labels_sha256'] = hashlib.sha256(label_path.read_bytes()).hexdigest()
                    row['scope_note'] = 'Known packaged dependency labels evaluated separately from full build graph; packaging-added UNKNOWN retained. Failed payload corroboration counts as missing known components, not hidden coverage.'
        rows.append(row)
    report={'candidate_unchanged':unchanged,'rows':rows,'target_per_language':20,
            'limitation':'Expansion strata reported separately, fixed fixture paths for inventory scoring; no generic ownership or aggregate production success claim.'}
    atomic_json(ROOT/'benchmarks/results/expanded-v1/status.json',report)
    for row in rows:
        if row['status']=='PAIRED':print(row['project'],row['components'],row['direct']['status'])


if __name__=='__main__':
    main()

"""Post-prediction independent control evaluation; never feeds reference to tools."""
import hashlib
import json

from compare_java_js import all_components, coord
from http_integration import command
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from run import ROOT, atomic_json
from score_project_components import metrics


def main():
    output = ROOT/'benchmarks/results/petclinic-rest-frozen-control-v1'
    documents = {}
    registry = Registry()
    schemas = ROOT/'benchmarks/references/trivy-java-source-v1/schemas'
    for path in schemas.glob('*.json'):
        schema = json.loads(path.read_bytes())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    validator = Draft7Validator(json.loads((schemas/'bom-1.7.schema.json').read_bytes()), registry=registry)
    for mode in ('image', 'source'):
        if json.loads((output/mode/'run.json').read_bytes())['exit_code'] != 0:
            raise ValueError('Failed candidate output cannot be scored as success')
        documents[mode] = json.loads((output/mode/'sbom.json').read_bytes())
        validator.validate(documents[mode])
    # Both frozen prediction paths completed before oracle access.
    pair = ROOT/'benchmarks/references/paired-petclinic-rest-v1'
    receipt = json.loads((pair/'receipt.json').read_bytes())
    for relative, digest in receipt['reference_hashes'].items():
        if hashlib.sha256((pair/relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Immutable reference changed')
    work = ROOT/'benchmarks/.work/paired-petclinic-rest-v1'
    if command(['git', '-C', str(work/'src'), 'rev-parse', 'HEAD']) != receipt['commit'] or command(['git', '-C', str(work/'src'), 'status', '--porcelain']):
        raise ValueError('Control source commit/tree differs')
    image_ids = [prop['value'] for prop in documents['image']['metadata']['component']['properties'] if prop['name'] == 'aquasecurity:trivy:ImageID']
    if image_ids != [receipt['image_binding']['config_digest']]:
        raise ValueError('Candidate image binding differs')
    reference = json.loads((pair/'sbom.json').read_bytes())
    owner = coord(reference['metadata']['component'])
    label_path = ROOT/'benchmarks/results/petclinic-rest-packaging-labels-v1/report.json'
    labels = json.loads(label_path.read_bytes())
    if labels['commit'] != receipt['commit'] or labels['unlabelled_build_reference']:
        raise ValueError('Incomplete or differently bound packaging labels')
    expected = set(labels['packaged'])
    predicted = {coord(component) for component in all_components(documents['image']) if coord(component) and any(
        prop.get('name') == 'aquasecurity:trivy:FilePath' and prop.get('value', '').lstrip('/').startswith('application/')
        for prop in component.get('properties', []))} - {owner}
    source_rows = json.loads((output/'source/owner-predictions.json').read_bytes())['owners']
    rows = [row for row in source_rows if row['path'] == 'pom.xml' and row['owner'] == owner]
    actual_direct = set(rows[0]['direct']) if len(rows) == 1 else set()
    expected_direct = set(labels['root_direct_build'])
    final = json.loads((work/'analysis/final.cdx.json').read_bytes())
    baseline = {coord(component) for component in all_components(final) if coord(component) and any(
        prop.get('name', '').startswith('syft:location:') and prop.get('name', '').endswith(':path')
        and prop.get('value', '').startswith('/application/') for prop in component.get('properties', []))} - {owner}
    identity_present = {value for value in expected if any(candidate.rsplit('@', 1)[0] == value.rsplit('@', 1)[0] for candidate in predicted)}
    report = {'project': receipt['project'], 'commit': receipt['commit'], 'partition': 'fresh_holdout_first_frozen_candidate_evaluation',
        'candidate_kind': 'external passive Trivy0.75.0 image inventory + source owner graph; NOT service final output',
        'runtime_changed': False, 'candidate_tuned_on_control': False, 'source_clean_verified': True, 'image_binding_verified': True,
        'schemas_valid': True, 'packaging_labels_sha256': hashlib.sha256(label_path.read_bytes()).hexdigest(),
        'components_conservative_unknown_extra_as_fp': metrics(predicted, expected),
        'component_missing': sorted(expected-predicted), 'component_extra': sorted(predicted-expected),
        'component_version_accuracy_matched_identity': len(expected & predicted)/len(identity_present) if identity_present else None,
        'component_exact_version_coverage': len(expected & predicted)/len(expected) if expected else None,
        'component_label_coverage': {'build_artifacts_labelled': labels['resolved_artifact_labels'],
            'build_reference_components': labels['build_reference_components'], 'packaged_labelled': len(expected),
            'packaged_unknown': len(labels['unknown_packaged'])},
        'root_direct_build_compile_runtime': metrics(actual_direct, expected_direct),
        'direct_missing': sorted(expected_direct-actual_direct), 'direct_extra': sorted(actual_direct-expected_direct),
        'owner_coverage': {'expected': 1, 'resolved': len(rows), 'unknown_targets': rows[0]['unknown_targets'] if len(rows) == 1 else None},
        'direct_scope': 'Build-resolved compile/runtime declarations excluding test/provided/system; includes starters and annotation processor intentionally absent from packaged image',
        'direct_packaging_counts': {'packaged': len(labels['root_direct_packaged']), 'not_packaged': len(labels['root_direct_not_packaged'])},
        'baseline_service_final_components': metrics(baseline, expected), 'baseline_service_summary': json.loads((work/'analysis/summary.json').read_bytes()),
        'known_baseline_direct_unmatched': len(expected_direct),
        'performance': {mode: json.loads((output/mode/'run.json').read_bytes())['elapsed_seconds'] for mode in ('image', 'source')},
        'limitations': ['One fresh Java project, not full20+20 corpus acceptance', 'No candidate runtime integration or generic image-owner/payload policy',
                       'Packaging-added jarmode artifact remains UNKNOWN and conservatively charged FP', 'Mirror metadata responses not hash-frozen; service network hardening not done',
                       'Previously disclosed Javalin/Petclinic/Pino/Nest remain development/regression, not fresh controls', 'Do not tune on this control and continue calling it independent']}
    atomic_json(output/'evaluation.json', report)
    print(json.dumps({key: report[key] for key in ('components_conservative_unknown_extra_as_fp', 'root_direct_build_compile_runtime', 'baseline_service_final_components')}))


if __name__ == '__main__':
    main()

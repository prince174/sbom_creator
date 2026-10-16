"""Post-only delivered-artifact scoring beside immutable R108 historical scopes.

Truth labels are constructed from controlled build/image bytes without reading a
prediction. This evaluator projects *every* final Maven coordinate below each
controlled owner prefix. It never keeps only predictions whose hash/path occurs
in the reference. Incomplete labels yield a conservative partial-reference view,
not a claim of complete image recall or production acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from compare_java_js import all_components, coord
from evaluate_mvp_r108 import prepare
from evaluate_mvp_runtime import CASES, macro
from evaluate_seekable_payload import aggregate
from run import ROOT, atomic_json
from score_project_components import metrics

DEFAULT_PREDICTIONS = ROOT / 'benchmarks/results/mvp-r108-v1'
DEFAULT_LABELS = ROOT / 'benchmarks/results/reactor-packaged-nested-r109-v3'
DEFAULT_OUTPUT = ROOT / 'benchmarks/results/reactor-packaged-evaluation-r109-v2'
PRIMARY_STATUS = 'VERIFIED_EFFECTIVE_PRIMARY_SHA256'
SCOPE = (
    'GAV set per controlled owner prefix, known delivered complete JAR bytes labelled by '
    'independent controlled-build SHA256; all projected final Maven coordinates retained; '
    'own primary root excluded only at an independently attested exact primary virtual path'
)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def paths(component):
    """Preserve physical and virtual distinctions when excluding the application root."""
    physical, virtual = set(), set()
    for prop in component.get('properties', []):
        name, value = prop.get('name', ''), prop.get('value')
        if not isinstance(value, str):
            continue
        if name.startswith('syft:location:') and name.endswith(':path'):
            physical.add(value)
        elif name == 'syft:metadata:virtualPath':
            virtual.add(value)
    return physical, virtual


def root_paths(module):
    """A filename or an owner PURL alone cannot establish the root exclusion."""
    owner, prefix = module['owner'], module['image_prefix']
    result = set()
    for primary in module.get('primary_outputs', []):
        path, digest = primary.get('image_path'), primary.get('sha256')
        if (primary.get('status') == PRIMARY_STATUS and primary.get('owner') == owner
                and isinstance(path, str) and path.startswith(prefix)
                and isinstance(digest, str) and len(digest) == 64
                and all(char in '0123456789abcdef' for char in digest)):
            result.add(path)
    return result


def projected_components(document, module):
    """No predicted component is filtered by the expected dependency set or SHA."""
    owner, prefix = module['owner'], module['image_prefix']
    attested_roots = root_paths(module)
    actual, root_exclusions, observations = set(), [], []
    for component in all_components(document):
        identity = coord(component)
        if not identity or not identity.startswith('pkg:maven/'):
            continue
        physical, virtual = paths(component)
        in_scope = {path for path in physical | virtual if path.startswith(prefix)}
        if not in_scope:
            continue
        # A nested instance with the same owner coordinate remains eligible. An
        # ambiguous multi-location observation cannot be silently removed either.
        exact_root = (identity == owner and len(physical) == 1 and physical <= attested_roots
                      and virtual == physical)
        if exact_root:
            root_exclusions.append({'coordinate': identity, 'paths': sorted(physical),
                                    'bom_ref': component.get('bom-ref')})
            continue
        actual.add(identity)
        observations.append({'coordinate': identity, 'paths': sorted(physical),
                             'virtual_paths': sorted(virtual), 'bom_ref': component.get('bom-ref')})
    return actual, observations, root_exclusions


def validate_module(module):
    """Reject labels that drop rows or infer completeness from a prediction."""
    prefix, owner = module.get('image_prefix'), module.get('owner')
    if (not isinstance(prefix, str) or not prefix.startswith('/application/')
            or not prefix.endswith('/') or '..' in prefix.split('/')
            or not isinstance(owner, str) or not owner.startswith('pkg:maven/')):
        raise ValueError('Invalid controlled owner scope')
    known = set()
    for group in ('known_file_labels', 'nested_file_labels'):
        for entry in module.get(group, []):
            identity, digest = entry.get('coordinate'), entry.get('sha256')
            if (not isinstance(identity, str) or not identity.startswith('pkg:maven/')
                    or '@' not in identity or not isinstance(digest, str) or len(digest) != 64
                    or any(char not in '0123456789abcdef' for char in digest)):
                raise ValueError('Invalid independently labelled delivered archive')
            path = entry.get('image_path', entry.get('outer_image_path'))
            if not isinstance(path, str) or not path.startswith(prefix):
                raise ValueError('Delivered archive escaped owner scope')
            if group == 'nested_file_labels' and entry.get('entry_crc_verified') is not True:
                raise ValueError('Nested physical label needs a complete member CRC check')
            known.add(identity)
    declared = module.get('known_delivered_coordinate_set')
    if not isinstance(declared, list) or len(declared) != len(set(declared)) or set(declared) != known:
        raise ValueError('Known delivered set must contain every independently labelled GAV')
    independently_resolved_primary = {(primary['image_path'], primary['sha256'])
                                     for primary in module.get('primary_outputs', [])
                                     if primary.get('image_path') in root_paths(module)}
    unknown_standalone = [entry for entry in module.get('unknown_standalone_files', [])
                          if (entry.get('image_path'), entry.get('sha256'))
                          not in independently_resolved_primary]
    unknown = (len(unknown_standalone) + len(module.get('unknown_nested_files', []))
               + len(module.get('unknown_shaded_content', [])))
    unattested_primary = sum(primary.get('status') != PRIMARY_STATUS
                             for primary in module.get('primary_outputs', []))
    complete = module.get('complete_image_component_scope_attested') is True
    if complete and (unknown or unattested_primary):
        raise ValueError('Incomplete packaging evidence cannot attest a complete component scope')
    return known, unknown, unattested_primary, complete


def score_module(document, module):
    expected, unknown, unattested_primary, complete = validate_module(module)
    actual, observations, excluded = projected_components(document, module)
    result = metrics(actual, expected)
    matched_identities = {identity for identity in expected if any(
        candidate.rsplit('@', 1)[0] == identity.rsplit('@', 1)[0] for candidate in actual)}
    return {'path': module['path'], 'owner': module['owner'], 'image_prefix': module['image_prefix'],
            'scope': SCOPE, 'complete_image_component_scope_attested': complete,
            'status': 'COMPLETE_REFERENCE_SCOPE' if complete else 'PARTIAL_REFERENCE_SCOPE',
            'known_delivered_conservative': result,
            'precision_interpretation': ('exact within attested component scope' if complete
                                         else 'conservative lower bound; unlabelled real components may be charged FP'),
            'recall_interpretation': ('complete delivered component recall' if complete
                                      else 'recall against known delivered GAVs only; global image recall UNKNOWN'),
            'versions': {'matched_identity_count': len(matched_identities),
                         'exact_version_tp': len(actual & expected),
                         'version_accuracy_matched_identity': (len(actual & expected) / len(matched_identities)
                                                              if matched_identities else None),
                         'exact_version_coverage_known_delivered': (len(actual & expected) / len(expected)
                                                                    if expected else None)},
            'count_delta_known_reference': len(actual) - len(expected),
            'missing_known_delivered': sorted(expected - actual),
            'extra_conservatively_charged_fp': sorted(actual - expected),
            'known_delivered_coordinate_count': len(expected),
            'projected_final_coordinate_count': len(actual),
            'unknown_packaging_observations': unknown,
            'unattested_primary_candidates': unattested_primary,
            'artifact_scope_complete': (module.get('artifact_scope_complete') is True
                                        or module.get('complete_delivered_archive_scope_attested') is True),
            'incomplete_scope_reasons': module.get('incomplete_scope_reasons', []),
            'independently_attested_root_exclusions': excluded,
            'projected_final_observations': observations,
            'empty_reference_is_positive_success': False,
            'acceptance': False}


def score_repository(document, report):
    modules = report['modules']
    prefixes = [module['image_prefix'] for module in modules]
    if len(prefixes) != len(set(prefixes)) or any(
            first.startswith(second) for first in prefixes for second in prefixes if first != second):
        raise ValueError('Owner prefixes must be unique and non-overlapping')
    rows = [score_module(document, module) for module in modules]
    positive = [row for row in rows if row['known_delivered_coordinate_count']]
    scored = [row['known_delivered_conservative'] for row in rows]
    version_tp = sum(row['versions']['exact_version_tp'] for row in rows)
    identity_count = sum(row['versions']['matched_identity_count'] for row in rows)
    expected_count = sum(row['known_delivered_coordinate_count'] for row in rows)
    return {'rows': rows, 'known_delivered_conservative_micro': aggregate(scored),
            'known_delivered_macro_positive_owners': macro([
                row['known_delivered_conservative'] for row in positive]),
            'owner_count': len(rows), 'positive_known_reference_owners': len(positive),
            'empty_known_reference_owners': len(rows) - len(positive),
            'complete_image_component_scope_owners': sum(
                row['complete_image_component_scope_attested'] for row in rows),
            'partial_reference_scope_owners': sum(
                not row['complete_image_component_scope_attested'] for row in rows),
            'complete_delivered_archive_scope_owners': sum(row['artifact_scope_complete'] for row in rows),
            'unknown_packaging_observations': sum(row['unknown_packaging_observations'] for row in rows),
            'unattested_primary_candidates': sum(row['unattested_primary_candidates'] for row in rows),
            'known_reference_instances': expected_count,
            'predicted_coordinate_instances': sum(row['projected_final_coordinate_count'] for row in rows),
            'count_delta_known_reference': sum(row['count_delta_known_reference'] for row in rows),
            'versions': {'version_accuracy_matched_identity': version_tp / identity_count if identity_count else None,
                         'exact_version_coverage_known_delivered': version_tp / expected_count if expected_count else None,
                         'exact_version_tp': version_tp, 'matched_identity_count': identity_count},
            'acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions', type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument('--labels', type=Path, default=DEFAULT_LABELS)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output, labels = args.output.resolve(), args.labels.resolve()
    if output.exists():
        raise FileExistsError('Preserve completed evaluation namespace')
    # Validate all predictions/freeze, schemas and no-oracle provenance before
    # opening the separately created packaged truth labels below.
    requested, predictions = prepare(args.predictions.resolve())
    historical_path = args.predictions.resolve() / 'evaluation.json'
    historical = read(historical_path)
    report_path = labels / 'report.json'
    label_report = read(report_path)
    label_manifest = read(labels / 'input-manifest.json')
    if (label_report.get('post_only') is not True
            or label_report.get('new_scans_builds_classifier_input_changes') is not False
            or label_manifest.get('post_only') is not True
            or label_manifest.get('prediction_or_classifier_inputs_read') is not False):
        raise ValueError('Independent post-only label provenance is required')
    reports = {}
    for case in requested:
        if case == 'boot':
            continue
        prediction = predictions[case]
        if prediction['analysis'] is None:
            document = {'components': []}
        else:
            document = read(prediction['analysis'] / 'final.cdx.json')
        candidates = [row for row in label_report['reports'] if row['pair'] == CASES[case]]
        if len(candidates) != 1:
            raise ValueError('One bound packaged reference per reactor is required')
        labelled = candidates[0]
        bound_report_path = labels / (CASES[case] + '.json')
        if (sha(bound_report_path) != label_manifest.get('output_reports', {}).get(bound_report_path.name)
                or read(bound_report_path) != labelled):
            raise ValueError('Packaged report differs from its separately hashed output manifest')
        expected_config = labelled['actual_oci_binding']['config_digest']
        if (prediction['analysis'] is not None and expected_config !=
                prediction['provenance']['image']['image_config_digest']):
            raise ValueError('Packaged truth and final SBOM image config differ')
        reports[case] = score_repository(document, labelled)
        reports[case].update(output_sha256=prediction['hashes'],
                             historical_conservative_r108_components=historical['reports'][case]['components_micro'])
    output.mkdir(parents=True)
    (output / 'executed-evaluator-source.py').write_bytes(Path(__file__).read_bytes())
    atomic_json(output / 'input-manifest.json', {
        'evaluator_sha256': sha(Path(__file__)),
        'predictions_marker_sha256': sha(args.predictions.resolve() / 'predictions-complete.json'),
        'prediction_freeze_sha256': sha(args.predictions.resolve() / 'freeze.json'),
        'historical_r108_evaluation_sha256': sha(historical_path),
        'new_packaged_report_sha256': sha(report_path),
        'new_packaged_input_manifest_sha256': sha(labels / 'input-manifest.json'),
        'evaluator_dependency_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (
            ROOT / 'benchmarks/evaluate_mvp_r108.py', ROOT / 'benchmarks/evaluate_mvp_runtime.py',
            ROOT / 'benchmarks/evaluate_seekable_payload.py', ROOT / 'benchmarks/compare_java_js.py',
            ROOT / 'benchmarks/score_project_components.py')},
        'post_only': True, 'no_new_scanner_or_classifier_run': True})
    result = {'post_only': True, 'runtime_changed': False, 'predictions_changed': False,
              'historical_scores_or_scopes_changed': False, 'prediction_version': 'R108',
              'label_version': 'R109', 'fresh_scanners': False, 'fresh_physical_predictions': False,
              'new_scope': SCOPE, 'reports': reports,
              'known_delivered_conservative_micro': aggregate([
                  report['known_delivered_conservative_micro'] for report in reports.values()]),
              'known_delivered_macro_across_repositories': macro([
                  report['known_delivered_conservative_micro'] for report in reports.values()]),
              'historical_r108_all_four_java_components_micro': historical['java_components_micro'],
              'acceptance': False,
              'limitations': [
                  'Truth set was independently constructed from delivered controlled-build SHA256, never prediction intersection',
                  'Partial labels yield lower-bound precision and recall of known delivered GAVs only; full-image recall is UNKNOWN',
                  'All final projected Maven components are retained, including packaging extras and unresolved identities',
                  'Primary root exclusion requires a recorded effective-output SHA256 and exact physical/virtual path',
                  'Opaque shaded content, unknown nested identities and unattested primary outputs remain explicit',
                  'Owner instances are not independent repositories; disclosed development cases are not blind acceptance',
                  'GAV scoring does not independently attest classifier/type qualifiers, publisher authenticity or execution',
                  'No direct/source graph accuracy is claimed by this component-only scoring view']}
    atomic_json(output / 'evaluation.json', result)
    print(json.dumps({case: report['known_delivered_conservative_micro'] for case, report in reports.items()}))


if __name__ == '__main__':
    main()

"""POST-only six-Java evaluation with unchanged historical and delivered views.

No reference/packaging label is opened until all six predictions pass preflight
and the root explicitly authorizes the completed set. This never runs a scanner,
classifier, build or physical reader. Known delivered scope remains partial where
shaded/packaging identities are unlabelled; historical UNKNOWN scopes stay visible.
"""
from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path

import evaluate_mvp_r110 as held
from compare_java_js import all_components, coord
from evaluate_mvp_runtime import evaluate_boot, evaluate_reactor, macro
from evaluate_reactor_packaged_r109 import score_repository
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import projected
from replay_java_db_peer_r111 import component_instances, image_id
from run import ROOT, atomic_json
from run_mvp_r110 import safe_relative, sha

from sbom_creator.validation import validate_cyclonedx

PREDICTIONS = ROOT / 'benchmarks/results/mvp-r112-java-v1'
OUTPUT = ROOT / 'benchmarks/results/mvp-r112-evaluation-v1'
LABELS = ROOT / 'benchmarks/results/reactor-packaged-nested-r109-v4'
CASES = {
    'microservices': 'paired-petclinic-microservices-r104',
    'boot': 'paired-spring-petclinic-v1',
    'javalin': 'paired-javalin-reactor-v1',
    'dropwizard': 'paired-dropwizard-reactor-v1',
    'rest': 'paired-petclinic-rest-v1',
    'dbcp': 'paired-commons-dbcp-v1',
}
REACTORS = ('microservices', 'javalin', 'dropwizard')
VIEWS = ('final', 'os', 'full')


def read(path):
    return json.loads(Path(path).read_bytes())


def completion_valid(marker, freeze, freeze_hash):
    cases = list(CASES)
    if (marker.get('oracle_read') is not False or marker.get('cases') != cases
            or marker.get('freeze_sha256') != freeze_hash
            or marker.get('all_predictions_terminal_before_reference_access') is not True
            or marker.get('all_frozen_source_tool_database_image_catalog_inputs_unchanged') is not True):
        raise ValueError('The complete sealed six-case prediction set is required before oracle access')
    done, failed = marker.get('completed', []), marker.get('failed', [])
    if (len(done) != len(set(done)) or len(failed) != len(set(failed))
            or set(done) & set(failed) or set(done) | set(failed) != set(cases)):
        raise ValueError('Terminal case statuses must be complete and non-overlapping')
    expected = {'oracle_read': False, 'source_input': False, 'project_execution': False,
        'reference_build_cache_read': False, 'fresh_syft_image_scans': False,
        'fresh_trivy_image_scans': True, 'fresh_physical_reads': True,
        'actual_service_publisher': True, 'fresh_blind_independent_claim': False,
        'java_archive_components_default': True, 'java_archive_components_override_supplied': False,
        'java_nested_windows_default': False, 'network_downloads_permitted': False,
        'build_or_registry_acquisition_permitted': False}
    if freeze.get('cases') != cases or any(freeze.get(key) is not value for key, value in expected.items()):
        raise ValueError('The default image-only cached-Syft/fresh-Trivy execution mode differs')


def source_valid(output, frozen):
    source = output / 'executed-source'
    if len(frozen) != 48:
        raise ValueError('All 48 current source/schema files must be frozen')
    actual = {path.relative_to(source).as_posix() for path in source.rglob('*') if path.is_file()
              and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    if actual != set(frozen):
        raise ValueError('Missing or unsealed executing source/schema files')
    for relative, expected in frozen.items():
        path = safe_relative(relative)
        if '__pycache__' in path.parts or path.suffix == '.pyc' or sha(source / path) != expected:
            raise ValueError('Executing source freeze changed or contains generated cache')


def preflight(output):
    """Only prediction/code/image/database inputs are read here; never truth."""
    marker, freeze = read(output / 'predictions-complete.json'), read(output / 'freeze.json')
    completion_valid(marker, freeze, sha(output / 'freeze.json'))
    if sha(output / 'executed-runner.py') != freeze.get('runner_sha256'):
        raise ValueError('Executed prediction runner changed')
    source_valid(output, freeze.get('code_sha256', {}))
    for relative, expected in freeze.get('input_sha256', {}).items():
        path = safe_relative(relative)
        if ('.m2' in {part.lower() for part in path.parts}
                or path.as_posix().lower().startswith('benchmarks/references/')
                or sha(ROOT / path) != expected):
            raise ValueError('Frozen image/catalog/public-cache input changed or is a build cache')
    databases = [(name, value) for name, value in freeze.get('input_sha256', {}).items()
                 if name.endswith('/java-db/trivy-java.db')]
    metadatas = [(name, value) for name, value in freeze.get('input_sha256', {}).items()
                if name.endswith('/java-db/metadata.json')]
    if (len(databases) != 1 or len(metadatas) != 1
            or databases[0][1] != freeze.get('database_sha256')
            or metadatas[0][1] != freeze.get('database_metadata_sha256')
            or freeze.get('versions_required') != {'syft': '1.51.1', 'trivy': '0.75.0'}):
        raise ValueError('One complete public DB/metadata snapshot and pinned producer versions are required')
    tools = {'syft': ROOT / '.tools/syft/syft.exe',
             'trivy': ROOT / 'benchmarks/.work/trivy-r34/trivy.exe',
             'crane': ROOT / 'benchmarks/.work/crane-r94/crane.exe'}
    if set(freeze.get('tool_sha256', {})) != set(tools) or any(
            sha(path) != freeze['tool_sha256'][name] for name, path in tools.items()):
        raise ValueError('Frozen producer/converter tools changed')
    prepared = {}
    for name, pair in CASES.items():
        folder = output / name
        invocation, run = read(folder / 'invocation.json'), read(folder / 'run.json')
        archive = f'benchmarks/.work/{pair}/image.tar'
        flags = {'oracle_read': False, 'source_input': False, 'repository_url': None,
                 'commit': None, 'project_execution': False, 'fresh_syft_image_scan': False,
                 'fresh_trivy_image_scan': True, 'fresh_physical_reads': True,
                 'actual_service_publisher': True, 'java_archive_components_default': True,
                 'java_archive_components_override_supplied': False}
        if (any(invocation.get(key) is not value for key, value in flags.items())
                or invocation.get('archive') != archive
                or invocation.get('archive_sha256') != freeze['input_sha256'].get(archive)
                or invocation.get('database_sha256') != freeze.get('database_sha256')
                or invocation.get('database_metadata_sha256') != freeze.get('database_metadata_sha256')
                or run.get('oracle_read') is not False
                or sha(folder / 'run.json') != marker.get('run_sha256', {}).get(name)):
            raise ValueError('Per-case no-oracle execution/input seals differ')
        analysis = folder / 'analysis'
        if run.get('status') == 'FAILED':
            if name not in marker['failed'] or analysis.exists() or run.get('final_published') is not False:
                raise ValueError('Failed case has unvalidated publication or inconsistent status')
            prepared[name] = {'analysis': None, 'run': run, 'hashes': {}}
            continue
        if run.get('status') != 'completed' or name not in marker['completed']:
            raise ValueError('Unfinished prediction cannot be evaluated')
        if any(run.get(key) is not value for key, value in {
                'source_input': False, 'fresh_syft_image_scan': False, 'fresh_trivy_image_scan': True,
                'fresh_physical_reads': True, 'actual_service_publisher': True,
                'java_archive_components_default': True}.items()):
            raise ValueError('Completed case lost its actual execution-mode evidence')
        sealed = run.get('output_sha256', {})
        for filename, expected in sealed.items():
            if Path(filename).name != filename or sha(analysis / filename) != expected:
                raise ValueError('A published output changed after prediction')
        required = ('source.syft.json', 'image.syft.json', 'image-original.syft.json',
                    'image-peer.cdx.json', 'image-identity-audit.json', 'selected.syft.json',
                    'provenance.json', 'summary.json', *(view + '.cdx.json' for view in VIEWS))
        if any(filename not in sealed for filename in required):
            raise ValueError('Every raw/evidence and final/os/full document must be sealed')
        hashes = {}
        for view in VIEWS:
            path = analysis / (view + '.cdx.json')
            validate_cyclonedx(read(path))
            hashes[view] = sha(path)
        provenance, summary = read(analysis / 'provenance.json'), read(analysis / 'summary.json')
        if (read(analysis / 'source.syft.json').get('artifacts') != []
                or provenance.get('source_kind') != 'not-provided' or summary.get('status') != 'succeeded'
                or provenance.get('request', {}).get('repository_url') is not None
                or provenance.get('request', {}).get('commit') is not None):
            raise ValueError('Only completed image-only publications are eligible')
        engine = provenance.get('image', {}).get('java_identity_engine', {})
        if (engine.get('database_sha256') != freeze.get('database_sha256')
                or engine.get('database_metadata_sha256') != freeze.get('database_metadata_sha256')):
            raise ValueError('Published identity engine used another public DB snapshot')
        prepared[name] = {'analysis': analysis, 'run': run, 'hashes': hashes,
                          'provenance': provenance, 'summary': summary}
    return freeze, prepared


def multiset(document):
    """All ecosystems and component instances, including OS, not only GAVs."""
    return Counter(json.dumps([component.get(key) for key in ('type', 'group', 'name', 'version', 'purl')],
                              sort_keys=True, separators=(',', ':'))
                   for component in all_components(document))


def metrics_row(actual, expected):
    from score_project_components import metrics
    matched = {value for value in expected if any(
        candidate.rsplit('@', 1)[0] == value.rsplit('@', 1)[0] for candidate in actual)}
    return {'components': metrics(actual, expected),
            'versions': {'exact_version_tp': len(actual & expected), 'matched_identity_count': len(matched),
                'version_accuracy_matched_identity': len(actual & expected) / len(matched) if matched else None,
                'exact_version_coverage_known_delivered': len(actual & expected) / len(expected) if expected else None},
            'count_delta': len(actual) - len(expected), 'missing': sorted(expected - actual),
            'extra_conservatively_charged_fp': sorted(actual - expected)}


def versions_aggregate(rows):
    exact = sum(row['exact_version_tp'] for row in rows)
    matched = sum(row['matched_identity_count'] for row in rows)
    expected = sum(row['expected_count'] for row in rows)
    return {'exact_version_tp': exact, 'matched_identity_count': matched, 'known_reference_instances': expected,
            'version_accuracy_matched_identity': exact / matched if matched else None,
            'exact_version_coverage_known_delivered': exact / expected if expected else None}


def baseline(name):
    prefix = ('mvp-r110-held-controls-v1/' + name if name in ('rest', 'dbcp')
              else 'mvp-r108-v1/java/' + name)
    return ROOT / 'benchmarks/results' / prefix / 'analysis'


def baseline_hashes():
    """Seal every prior input used for all-view and selected-ID comparisons."""
    names = (*(view + '.cdx.json' for view in VIEWS), 'selected.syft.json', 'image-peer.cdx.json')
    return {name: {filename: sha(baseline(name) / filename) for filename in names} for name in CASES}


def evaluator_hashes():
    """Explicit local Python helpers; imported runtime is already snapshot-sealed."""
    names = ('evaluate_mvp_r112_java', 'evaluate_mvp_r110', 'compare_java_js',
             'evaluate_mvp_runtime', 'evaluate_reactor_packaged_r109', 'evaluate_seekable_payload',
             'evaluate_trivy_payload_bridge', 'score_project_components', 'run', 'run_mvp_r110',
             'replay_java_db_peer_r111')
    return {name + '.py': sha(ROOT / 'benchmarks' / (name + '.py')) for name in names}


def all_view_regression(prediction, old):
    result = {'baseline': old.relative_to(ROOT).as_posix(), 'views': {}}
    for view in VIEWS:
        previous = multiset(read(old / (view + '.cdx.json')))
        current = multiset(read(prediction['analysis'] / (view + '.cdx.json'))) if prediction['analysis'] else Counter()
        result['views'][view] = {'all_component_coordinate_instances_equal': current == previous,
            'added_instances': sum((current - previous).values()), 'removed_instances': sum((previous - current).values()),
            'added': dict(current - previous), 'removed': dict(previous - current)}
    prior_ids = {row['id'] for row in read(old / 'selected.syft.json')['artifacts']}
    actual_ids = ({row['id'] for row in read(prediction['analysis'] / 'selected.syft.json')['artifacts']}
                  if prediction['analysis'] else set())
    result['selected_artifact_ids'] = {'equal': actual_ids == prior_ids,
                                      'added': sorted(actual_ids - prior_ids), 'removed': sorted(prior_ids - actual_ids)}
    return result


def raw_peer_regression(prediction, old):
    """Compare inventories with path/layer properties, ignoring random CDX IDs."""
    previous_document = read(old / 'image-peer.cdx.json')
    previous = component_instances(previous_document)
    current_document = (read(prediction['analysis'] / 'image-peer.cdx.json')
                        if prediction['analysis'] else None)
    current = component_instances(current_document) if current_document else Counter()
    current_config = image_id(current_document) if current_document else None
    prior_config = image_id(previous_document)
    return {'baseline': (old / 'image-peer.cdx.json').relative_to(ROOT).as_posix(),
        'baseline_sha256': sha(old / 'image-peer.cdx.json'),
        'current_sha256': (sha(prediction['analysis'] / 'image-peer.cdx.json')
                           if prediction['analysis'] else None),
        'raw_component_instances_equal': current == previous,
        'image_config_equal': current_config == prior_config,
        'current_image_config': current_config, 'prior_image_config': prior_config,
        'current_component_instances': sum(current.values()),
        'prior_component_instances': sum(previous.values()),
        'unchanged_instances': sum((current & previous).values()),
        'added_instances': sum((current - previous).values()),
        'removed_instances': sum((previous - current).values()),
        'added': dict(current - previous), 'removed': dict(previous - current),
        'compared_fields': 'type/group/name/version/PURL and all producer properties including FilePath/LayerDiffID/LayerDigest; random UUID and bom-ref excluded',
        'database_transition': 'new public DB versus same pinned prior Trivy image inventory; producer versions unchanged'}


def delivered_labels():
    """POST-only function: caller must have passed complete preflight/authorization."""
    report, manifest = read(LABELS / 'report.json'), read(LABELS / 'input-manifest.json')
    if (report.get('post_only') is not True or manifest.get('post_only') is not True
            or report.get('new_scans_builds_classifier_input_changes') is not False
            or manifest.get('prediction_or_classifier_inputs_read') is not False):
        raise ValueError('Independent unchanged delivered labels are required')
    result = {}
    for name in REACTORS:
        values = [row for row in report['reports'] if row['pair'] == CASES[name]]
        path = LABELS / (CASES[name] + '.json')
        if (len(values) != 1 or sha(path) != manifest.get('output_reports', {}).get(path.name)
                or read(path) != values[0]):
            raise ValueError('Delivered label set differs from its immutable output seal')
        result[name] = values[0]
    return result


def known_single(document, owner, expected, unknown):
    measured = metrics_row(projected(document, '/application/', owner), expected)
    row = {'path': '.', 'owner': owner, 'image_prefix': '/application/',
           'known_delivered_conservative': measured['components'], **{key: measured[key] for key in
                ('versions', 'count_delta', 'missing', 'extra_conservatively_charged_fp')},
           'known_delivered_coordinate_count': len(expected),
           'unknown_packaging_observations': unknown, 'complete_image_component_scope_attested': False,
           'scope': 'unchanged prior controlled known delivered project-dependency GAV scope'}
    return {'rows': [row], 'known_delivered_conservative_micro': measured['components'],
        'known_delivered_macro_positive_owners': macro([measured['components']]),
        'owner_count': 1, 'positive_known_reference_owners': int(bool(expected)),
        'empty_known_reference_owners': int(not expected), 'complete_image_component_scope_owners': 0,
        'partial_reference_scope_owners': 1, 'unknown_packaging_observations': unknown,
        'known_reference_instances': len(expected), 'count_delta_known_reference': measured['count_delta'],
        'versions': versions_aggregate([{**measured['versions'], 'expected_count': len(expected)}]),
        'acceptance': False}


def evaluate_all(predictions):
    """Every oracle/packaging read is below this explicit post-only boundary."""
    labels = delivered_labels()
    reports = {}
    for name, pair_name in CASES.items():
        prediction = predictions[name]
        pair = ROOT / 'benchmarks/references' / pair_name
        documents = {view: read(prediction['analysis'] / (view + '.cdx.json'))
                     if prediction['analysis'] else {'components': []} for view in VIEWS}
        if name in REACTORS or name == 'boot':
            historical = evaluate_reactor(pair, prediction) if name in REACTORS else evaluate_boot(pair, prediction)
        else:
            historical = held.evaluate_case(name, prediction)
        if name in REACTORS:
            if (prediction['analysis'] and labels[name]['actual_oci_binding']['config_digest'] !=
                    prediction['provenance']['image']['image_config_digest']):
                raise ValueError('New publication and same delivered labels bind different image configs')
            views = {view: score_repository(documents[view], labels[name]) for view in ('final', 'full')}
        else:
            owner = coord(read(pair / 'sbom.json')['metadata']['component'])
            if name == 'dbcp':
                expected = {row['coordinate'] for row in historical['known_standalone_labels']}
                unknown = len(historical['packaging_unknown'])
            else:
                path = ROOT / ('benchmarks/results/boot-packaging-labels-v3/report.json' if name == 'boot'
                               else 'benchmarks/results/petclinic-rest-packaging-labels-v1/report.json')
                single_labels = read(path)
                expected, unknown = set(single_labels['packaged']), len(single_labels['unknown_packaged'])
            views = {view: known_single(documents[view], owner, expected, unknown) for view in ('final', 'full')}
        old_document = read(baseline(name) / 'final.cdx.json')
        prior = (score_repository(old_document, labels[name]) if name in REACTORS
                 else known_single(old_document, owner, expected, unknown))
        current_rows, prior_rows = views['final']['rows'], prior['rows']
        if len(current_rows) != len(prior_rows):
            raise ValueError('Fixed owner reference view changed during comparison')
        for row, before in zip(current_rows, prior_rows, strict=True):
            expected_count = row['known_delivered_coordinate_count']
            if (expected_count != before['known_delivered_coordinate_count']
                    or any(row.get(key) != before.get(key) for key in ('path', 'owner', 'image_prefix'))):
                raise ValueError('Prior and current reference scope differs')
            old_metric, new_metric = before['known_delivered_conservative'], row['known_delivered_conservative']
            row['prior_same_scope_metrics'] = old_metric
            row['same_scope_delta'] = {key: new_metric[key] - old_metric[key] for key in ('tp', 'fp', 'fn')}
        historic_versions = []
        if name in REACTORS:
            for row in historical['rows']:
                if row['components'] is None:
                    continue
                module = pair / 'modules' / ('root' if row['path'] == '.' else row['path'])
                expected_historical = {coord(component) for component in all_components(read(module / 'sbom.json'))
                                       if coord(component)} - {row['owner']}
                actual_historical = projected(documents['final'], row['image_prefix'], row['owner'])
                exact = metrics_row(actual_historical, expected_historical)['versions']
                row['version_exact_counts_scored_scope'] = exact
                historic_versions.append({**exact, 'expected_count': len(expected_historical)})
        else:
            exact = metrics_row(projected(documents['final'], '/application/', owner), expected)['versions']
            historic_versions.append({**exact, 'expected_count': len(expected)})
        historical['versions_scored_scope'] = versions_aggregate(historic_versions)
        result = {'status': prediction['run']['status'], 'seconds': prediction['run'].get('elapsed_seconds'),
            'historical_conservative_scope': historical, 'known_delivered_views': views,
            'prior_same_known_delivered_final': prior,
            'all_final_os_full_inventory_regression': all_view_regression(prediction, baseline(name)),
            'raw_peer_inventory_regression': raw_peer_regression(prediction, baseline(name)),
            'output_sha256': prediction['hashes'],
            'whole_inventory_counts': {view: len(all_components(documents[view])) for view in VIEWS},
            'os_project_maven_observations_unscored': sorted({coord(c) for c in all_components(documents['os'])
                                                           if coord(c) and coord(c).startswith('pkg:maven/')}),
            'os_is_not_an_empty_project_accuracy_success': True}
        if prediction['analysis']:
            audit = read(prediction['analysis'] / 'image-identity-audit.json')
            result.update(runtime_summary=prediction['summary'],
                resources={key: audit.get(key) for key in ('jar_resources', 'layer_resources')},
                java_identity_engine=prediction['provenance']['image'].get('java_identity_engine'),
                observed_archive_component_proofs=len(prediction['provenance']['image'].get(
                    'identity_binding_envelope', {}).get('archive_presence', {})))
        reports[name] = result
    return reports


def summarize(reports):
    known = [report['known_delivered_views']['final'] for report in reports.values()]
    historical = [report['historical_conservative_scope'] for report in reports.values()]
    rows = [row for repository in known for row in repository['rows']]
    historical_metrics = [row.get('components', row.get('components_micro')) for row in historical]
    version_rows = [{**row['versions'], 'expected_count': row['known_delivered_coordinate_count']} for row in rows]
    weak = [{'case': name, 'path': row['path'], 'owner': row['owner'],
             'metrics': row['known_delivered_conservative'], 'versions': row['versions']}
            for name, report in reports.items() for row in report['known_delivered_views']['final']['rows']
            if any(row['known_delivered_conservative'][key] is None or row['known_delivered_conservative'][key] <= .9
                   for key in ('precision', 'recall')) or
               row['versions']['exact_version_coverage_known_delivered'] is None or
               row['versions']['exact_version_coverage_known_delivered'] <= .9]
    weak_repositories = [name for name, report in reports.items()
        if any(report['known_delivered_views']['final']['known_delivered_conservative_micro'][key] is None
               or report['known_delivered_views']['final']['known_delivered_conservative_micro'][key] <= .9
               for key in ('precision', 'recall'))
        or report['known_delivered_views']['final']['versions']['exact_version_coverage_known_delivered'] is None
        or report['known_delivered_views']['final']['versions']['exact_version_coverage_known_delivered'] <= .9]
    return {'same_known_delivered_final_micro': aggregate([row['known_delivered_conservative_micro'] for row in known]),
        'same_known_delivered_repository_macro': macro([row['known_delivered_conservative_micro'] for row in known]),
        'same_known_delivered_positive_owner_macro': macro([row['known_delivered_conservative'] for row in rows
                                                            if row['known_delivered_coordinate_count']]),
        'same_known_delivered_versions': versions_aggregate(version_rows),
        'historical_conservative_micro': aggregate(historical_metrics),
        'historical_conservative_repository_macro': macro(historical_metrics),
        'historical_conservative_scored_versions': versions_aggregate([
            {**row['versions_scored_scope'],
             'expected_count': row['versions_scored_scope']['known_reference_instances']} for row in historical]),
        'historical_unknown_scope_owners': sum(row.get('scope_unknown_owners', 0) for row in historical),
        'known_delivered_partial_reference_owners': sum(row['partial_reference_scope_owners'] for row in known),
        'unknown_packaging_observations': sum(row['unknown_packaging_observations'] for row in known),
        'empty_known_reference_owner_count': sum(row['empty_known_reference_owners'] for row in known),
        'known_delivered_owner_instances_not_independent_projects': len(rows),
        'independent_project_count_not_claimed': True, 'historically_disclosed_repository_count': len(reports),
        'count_delta_known_reference': sum(row['count_delta_known_reference'] for row in known),
        'weak_known_delivered_owners': weak,
        'weak_known_delivered_repositories': weak_repositories,
        'every_disclosed_repository_known_delivered_p_r_versions_over_90': not weak_repositories,
        'image_only_direct_unknown': aggregate([row['direct'] for row in historical]),
        'acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions', type=Path, default=PREDICTIONS)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--root-all-six-ready', action='store_true')
    args = parser.parse_args()
    if not args.root_all_six_ready:
        raise ValueError('Wait for explicit root ALL6READY after all predictions are sealed')
    output, prediction_root = args.output.resolve(), args.predictions.resolve()
    if output.exists():
        raise FileExistsError('Preserve every attempted or completed evaluator namespace')
    freeze, predictions = preflight(prediction_root)
    # First oracle reads occur only in evaluate_all(), after complete preflight.
    reports = evaluate_all(predictions)
    result = {'post_only': True, 'historical_scores_or_reference_views_changed': False,
        'prediction_mode': freeze['mode'], 'database_sha256': freeze['database_sha256'],
        'database_metadata_sha256': freeze['database_metadata_sha256'],
        'fresh_syft_image_scans': False, 'fresh_trivy_image_scans': True, 'fresh_physical_reads': True,
        'source_input': False, 'fresh_blind_independent_claim': False,
        'reports': reports, **summarize(reports),
        'limitations': ['Same six disclosed projects and same SHA-labelled reference views; no blind independent claim',
                       'Known delivered GAV recall is not complete global image recall where shaded/packaging scope is UNKNOWN',
                       'All projected coordinates are retained; packaging extras are conservative FP, known UNKNOWN predictions are FN',
                       'Historical native/CDX scope disagreements and raw build deltas remain separate and unchanged',
                       'Final/full project accuracy is separate from OS inventory; empty OS project scope is not a success',
                       'Conditional identity version accuracy and exact known-reference coverage are reported separately',
                       'Image inventory does not establish directness, execution or original CI graph; all direct edges UNKNOWN',
                       'Timing excludes cached Syft/acquisition; hard quota/RSS/concurrency coverage is not inferred']}
    output.mkdir(parents=True)
    shutil.copyfile(__file__, output / 'executed-evaluator.py')
    atomic_json(output / 'evaluation.json', result)
    atomic_json(output / 'input-manifest.json', {'post_only': True,
        'evaluator_sha256': sha(__file__), 'prediction_freeze_sha256': sha(prediction_root / 'freeze.json'),
        'evaluator_helper_sha256': evaluator_hashes(),
        'prediction_marker_sha256': sha(prediction_root / 'predictions-complete.json'),
        'delivered_label_report_sha256': sha(LABELS / 'report.json'),
        'delivered_label_manifest_sha256': sha(LABELS / 'input-manifest.json'),
        'evaluation_sha256': sha(output / 'evaluation.json'),
        'prior_output_sha256': baseline_hashes(),
        'prior_final_sha256': {name: sha(baseline(name) / 'final.cdx.json') for name in CASES}})
    print(json.dumps(result['same_known_delivered_final_micro']))


if __name__ == '__main__':
    main()

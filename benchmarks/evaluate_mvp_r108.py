"""Post-only Java scores for four completed R108 opt-in archive-component predictions.

The scanner inventories may be cached, but physical reads and service publication
are fresh. All four predictions finish before this evaluator opens an oracle.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from evaluate_mvp_r106 import view_regression
from evaluate_mvp_runtime import CASES, evaluate_boot, evaluate_reactor, macro, sha
from evaluate_seekable_payload import aggregate
from evaluate_trivy_payload_bridge import projected, read
from run import ROOT, atomic_json

from sbom_creator.validation import validate_cyclonedx


def frozen_code_path(output, name, expected):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unexpected frozen code path')
    candidates = [output / 'executed-source' / relative,
                  output / 'java/executed-source' / relative,
                  ROOT / relative]
    if relative.parts and relative.parts[0] == 'sbom_creator':
        candidates.append(ROOT / 'src' / relative)
    for path in candidates:
        if path.is_file() and sha(path) == expected:
            return path
    raise ValueError('Frozen executing code is missing or changed: ' + name)


def prepare(output):
    marker = read(output / 'predictions-complete.json')
    requested = marker.get('cases')
    if (marker.get('oracle_read') is not False or not isinstance(requested, list)
            or len(requested) != 4 or len(set(requested)) != 4 or set(requested) != set(CASES)):
        raise ValueError('All four distinct Java predictions must complete before evaluation')
    freeze = read(output / 'freeze.json')
    if not freeze.get('code_sha256') or freeze.get('oracle_read') is not False:
        raise ValueError('A no-oracle executing candidate freeze is required')
    if (marker.get('freeze_sha256') != sha(output / 'freeze.json')
            or freeze.get('java_nested_windows') is not True
            or freeze.get('java_archive_components') is not True
            or freeze.get('fresh_scanners') is not False
            or set(freeze.get('cases', [])) != set(requested)):
        raise ValueError('Prediction marker/candidate mode binding differs')
    if (set(marker.get('completed', [])) & set(marker.get('failed', []))
            or set(marker.get('completed', [])) | set(marker.get('failed', [])) != set(requested)):
        raise ValueError('Prediction completion statuses are inconsistent')
    if sha(ROOT / '.tools/syft/syft.exe') != freeze.get('syft_sha256'):
        raise ValueError('Pinned actual publisher binary changed')
    for name, expected in freeze['code_sha256'].items():
        frozen_code_path(output, name, expected)
    for name, expected in freeze.get('input_sha256', {}).items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or sha(ROOT / relative) != expected:
            raise ValueError('Frozen prediction input changed')
    prepared = {}
    for case in requested:
        folder = output / 'java' / case
        invocation, run = read(folder / 'invocation.json'), read(folder / 'run.json')
        if (invocation.get('oracle_read') is not False or run.get('oracle_read') is not False
                or invocation.get('repository_url') is not None or invocation.get('commit') is not None
                or invocation.get('source_input') is not False
                or invocation.get('java_nested_windows') is not True
                or invocation.get('java_archive_components') is not True):
            raise ValueError('Prediction must retain image-only/no-oracle provenance')
        archive = ROOT / 'benchmarks/.work' / CASES[case] / 'image.tar'
        archive_name = archive.relative_to(ROOT).as_posix()
        if (invocation.get('archive') != archive_name
                or sha(archive) != freeze.get('input_sha256', {}).get(archive_name)):
            raise ValueError('Prediction image bytes changed')
        analysis = folder / 'analysis'
        if run.get('status') == 'FAILED' and not analysis.exists():
            prepared[case] = {'run': run, 'analysis': None, 'hashes': {}}
            continue
        if run.get('status') != 'completed':
            raise ValueError('Unfinished prediction: ' + case)
        hashes = {}
        for view in ('final', 'os', 'full'):
            path = analysis / (view + '.cdx.json')
            validate_cyclonedx(read(path))
            hashes[view] = sha(path)
        provenance = read(analysis / 'provenance.json')
        if provenance.get('source_kind') != 'not-provided' or read(analysis / 'summary.json').get('status') != 'succeeded':
            raise ValueError('Unconfirmed image-only service publication')
        prepared[case] = {'run': run, 'analysis': analysis, 'hashes': hashes, 'provenance': provenance}
    return requested, prepared


def archive_evidence(prediction, baseline):
    """Report separate archive and class/resource facts without consulting labels."""
    image = prediction['provenance']['image']
    envelope = image['identity_binding_envelope']
    proofs = envelope.get('archive_presence', {})
    payload = image['payload_evidence']
    previous = read(baseline / 'provenance.json')['image']['payload_evidence']
    selected_ids = {artifact['id'] for artifact in read(prediction['analysis'] / 'selected.syft.json')['artifacts']}
    old_confirmed = {identity for identity, fact in previous.items() if fact.get('status') == 'confirmed'}
    new_confirmed = {identity for identity, fact in payload.items() if fact.get('status') == 'confirmed'}
    return {
        'reader_policy': envelope.get('reader_policy'),
        'confirmed_archive_instances': len(proofs),
        'unique_complete_sha256': len({fact['sha256'] for fact in proofs.values()}),
        'identity_method_counts': dict(Counter(fact['identity_method'] for fact in proofs.values())),
        'all_archive_proofs_complete_sha256_sha1_and_all_member_crc': (all(
            fact.get('kind') == 'complete_java_archive' and fact.get('status') == 'confirmed'
            and fact.get('chain_verified') is True and fact.get('zip_crc_verified') is True
            and len(fact.get('sha256', '')) == 64 and len(fact.get('sha1', '')) == 40
            for fact in proofs.values()) if proofs else None),
        'nested_crc_rechecked_instances': sum(fact.get('nested_crc_verified') is True for fact in proofs.values()),
        'actual_payload_status_for_archive_proofs': dict(Counter(
            payload.get(identity, {}).get('status', 'missing') for identity in proofs)),
        'selected_artifact_instances_with_archive_proof': len(selected_ids & set(proofs)),
        'archive_presence_and_payload_are_separate': True,
        'actual_payload_fact_mapping_equal_r107': payload == previous,
        'confirmed_payload_losses_vs_r107': sorted(old_confirmed - new_confirmed),
        'confirmed_payload_additions_vs_r107': sorted(new_confirmed - old_confirmed),
        'public_database_sha256': envelope.get('archive_database_sha256'),
        'public_database_and_trivy_peer_are_correlated': True,
        'publisher_authentication_or_global_gav_uniqueness_claimed': False,
    }


def evaluate(output, requested, predictions):
    # First component/reference oracle reads occur only below this boundary.
    reports = {}
    for case in requested:
        prediction = predictions[case]
        pair = ROOT / 'benchmarks/references' / CASES[case]
        result = (evaluate_boot(pair, prediction) if case == 'boot'
                  else evaluate_reactor(pair, prediction))
        run = prediction['run']
        result.update(status=run['status'], seconds=run.get('elapsed_seconds'),
                      output_sha256=prediction['hashes'],
                      execution_mode='opt-in experimental; cached inventories, fresh physical reads/publishing')
        baseline = ROOT / 'benchmarks/results/mvp-r107-v1/java' / case / 'analysis'
        result['r107_all_view_regression'] = view_regression(prediction['analysis'], baseline)
        if prediction['analysis']:
            result['runtime_summary'] = read(prediction['analysis'] / 'summary.json')
            result['java_reader_policy'] = prediction['provenance']['image'].get('java_reader_policy')
            audit = read(prediction['analysis'] / 'image-identity-audit.json')
            result['resources'] = {key: audit.get(key) for key in ('jar_resources', 'layer_resources')}
            result['archive_evidence'] = archive_evidence(prediction, baseline)
        if case != 'boot':
            before = read(baseline / 'final.cdx.json')
            after = read(prediction['analysis'] / 'final.cdx.json') if prediction['analysis'] else None
            for row in result['rows']:
                old_set = projected(before, row['image_prefix'], row['owner'])
                new_set = projected(after, row['image_prefix'], row['owner']) if after else set()
                row['r107_component_regression'] = {'added': sorted(new_set - old_set),
                                                   'removed': sorted(old_set - new_set)}
        reports[case] = result
    components = [row.get('components', row.get('components_micro')) for row in reports.values()]
    result = {'mode': 'actual service opt-in Java delivered-archive evidence; cached inventories, fresh physical reads and publisher',
              'source_input': False, 'fresh_scanners': False, 'fresh_physical_reads': True,
              'production_default_changed': False, 'experimental': True, 'java_archive_components': True,
              'same_reference_scopes_as_r107': True, 'reports': reports,
              'java_components_micro': aggregate(components),
              'java_components_macro_across_repositories': macro(components),
              'java_direct': aggregate([row['direct'] for row in reports.values()]),
              'operational_status': {'completed': sum(row['status'] == 'completed' for row in reports.values()),
                                     'failed': [case for case, row in reports.items() if row['status'] != 'completed']},
              'javascript': 'not rescanned or scored by this Java-only stage',
              'acceptance': False,
              'limitations': ['Four disclosed repositories, not fresh independent accuracy acceptance',
                              'Owner instances are not independent projects; unknown scopes retain all raw deltas',
                              'Image-only direct graph remains UNKNOWN/FN',
                              'Known build-reference components with unknown payload remain FN',
                              'GAV scoring does not independently validate classifier/type qualifiers',
                              'Timing excludes reused scanner acquisition/inventories; no hard-quota/RSS claim']}
    atomic_json(output / 'evaluation.json', result)
    print(json.dumps({case: row.get('components', row.get('components_micro'))
                      for case, row in reports.items()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/results/mvp-r108-v1')
    args = parser.parse_args()
    output = args.output.resolve()
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve completed evaluation')
    requested, prepared = prepare(output)
    evaluate(output, requested, prepared)


if __name__ == '__main__':
    main()

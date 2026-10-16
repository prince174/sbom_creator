"""POST-only comparison after both local image-only API downloads are sealed.

This evaluator cannot submit jobs, execute projects, scan or publish SBOMs. Build
references and packaged labels are opened only after both client reports and all
downloaded artifact hashes, schemas and image provenance pass preflight.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import tarfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ('final', 'os', 'full')
CASES = {'java-rest': 'java-rest-api-v1', 'javascript-nest': 'javascript-nest-api-v1'}
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')


def read(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_file(folder, name):
    if (type(name) is not str or not re.fullmatch(r'[a-z][a-z0-9.-]{0,79}\.json', name)
            or '..' in name or Path(name).name != name):
        raise ValueError('Unsafe artifact name')
    path = folder / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('A sealed regular artifact is required')
    return path


def coordinates(document):
    def collect(items):
        for component in items:
            yield component
            yield from collect(component.get('components', []))
    items = [*collect(document.get('components', [])),
             *collect(document.get('metadata', {}).get('component', {}).get('components', []))]
    return Counter(json.dumps([item.get(key) for key in ('type', 'group', 'name', 'version', 'purl')],
                              separators=(',', ':')) for item in items)


def validate_provenance(provenance, sample, original):
    image, request = provenance.get('image', {}), provenance.get('request', {})
    digest = sample.get('platform_digest')
    if (provenance.get('source_kind') != 'not-provided'
            or request.get('repository_url') is not None or request.get('commit') is not None
            or request.get('image') != sample.get('image')
            or not DIGEST.fullmatch(digest or '') or not sample['image'].endswith('@' + digest)
            or image.get('image_config_digest') != sample.get('config_digest')
            or image.get('platform_digest') != digest
            or image.get('image_digest') != digest
            or image.get('container_started') is not False
            or image.get('acquisition') == 'archive'):
        raise ValueError('Actual image-only registry provenance differs from the requested digest')
    source = original.get('source', {})
    encoded = source.get('metadata', {}).get('config', '')
    try:
        actual = 'sha256:' + hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest()
    except (TypeError, ValueError):
        raise ValueError('Original scanner image config is not valid base64') from None
    if source.get('type') != 'image' or actual != sample.get('config_digest'):
        raise ValueError('Original scanner config is not bound to the requested image')


def archive_platform(path, sample):
    """Input binding only, never a build-reference read."""
    if sha(path) != sample.get('archive_sha256'):
        raise ValueError('The unchanged immutable input archive hash differs')
    with tarfile.open(path) as archive:
        matches = archive.getmembers()
        target = 'blobs/sha256/' + sample['platform_digest'][7:]
        entries = [entry for entry in matches if entry.name == target]
        if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 4 * 1024**2:
            raise ValueError('Unique bounded platform manifest is required')
        raw = archive.extractfile(entries[0]).read(entries[0].size + 1)
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != sample['platform_digest']:
            raise ValueError('Exact platform manifest hash differs')
        document = json.loads(raw)
        if document.get('config', {}).get('digest') != sample['config_digest']:
            raise ValueError('Exact platform config binding differs')
        if [entry.get('digest') for entry in document.get('layers', [])] != sample.get('layer_digests'):
            raise ValueError('Exact original platform layers differ')


def prepare(root, workspace, validate, case_paths=None):
    """All completion gates occur before any reference/labels can be opened."""
    clients = {}
    for name, relative in CASES.items():
        folder = (case_paths or {}).get(name, workspace / relative)
        client_path = safe_file(folder, 'client-report.json')
        client = read(client_path)
        if (client.get('status') != 'succeeded' or client.get('submitted_once') is not True
                or client.get('partial_artifact') is not None or client.get('error') is not None):
            raise ValueError('Both API clients must finish successfully before oracle access')
        clients[name] = folder, client, sha(client_path)
    samples_path = workspace / 'samples.json'
    samples = read(samples_path)
    if samples.get('status') != 'passed' or samples.get('foreign_project_built') is not False:
        raise ValueError('Preserved immutable registry samples are required')
    prepared = {}
    for name, (folder, client, client_sha) in clients.items():
        sample = samples['samples'][name]
        if (sample.get('manifest_preserved') is not True or sample.get('config_preserved') is not True
                or sample.get('reference_or_source_accessed') is not False):
            raise ValueError('Registry input provenance is incomplete')
        rows = client.get('downloaded_artifacts', [])
        names = [row.get('name') for row in rows if isinstance(row, dict)]
        required = {view + '.cdx.json' for view in VIEWS} | {
            'provenance.json', 'source.syft.json', 'image.syft.json', 'summary.json'}
        if (not isinstance(rows, list) or len(names) != len(rows) or len(set(names)) != len(names)
                or not required <= set(names)):
            raise ValueError('Every downloaded artifact and all three views must be sealed')
        hashes = {}
        for row in rows:
            path = safe_file(folder, row['name'])
            actual = sha(path)
            if actual != row.get('sha256') or path.stat().st_size != row.get('bytes'):
                raise ValueError('A downloaded output changed after client completion')
            hashes[row['name']] = actual
        for view in VIEWS:
            validate(read(folder / (view + '.cdx.json')))
        provenance = read(folder / 'provenance.json')
        raw_name = 'image-original.syft.json' if 'image-original.syft.json' in hashes else 'image.syft.json'
        validate_provenance(provenance, sample, read(folder / raw_name))
        if read(folder / 'source.syft.json').get('artifacts') != []:
            raise ValueError('Image-only API prediction received a source catalog')
        if read(folder / 'summary.json').get('status') != 'succeeded':
            raise ValueError('Publisher did not complete')
        archive = root / sample['archive']
        if not archive.resolve().is_relative_to((root / 'benchmarks/.work').resolve()):
            raise ValueError('Registry sample archive is outside controlled inputs')
        archive_platform(archive, sample)
        prepared[name] = {'analysis': folder, 'provenance': provenance, 'sample': sample,
            'run': {'status': 'completed', 'elapsed_seconds': client['elapsed_seconds']},
            'hashes': {view: hashes[view + '.cdx.json'] for view in VIEWS},
            'all_downloaded_artifact_sha256': hashes, 'client_report_sha256': client_sha,
            'job_id': client['job_id']}
    return prepared, sha(samples_path)


def java_result(prediction):
    import evaluate_mvp_r110 as held
    # Existing reference function rechecks immutable receipt, actual OCI chain,
    # build/runtime TAR trees and original config; no historical freeze preflight.
    return held.evaluate_case('rest', prediction)


def javascript_result(prediction):
    from compare_java_js import all_components, coord, graph
    from evaluate_trivy_payload_bridge import projected, versions
    from paired_express import archive_binding
    from score_project_components import metrics

    pair = ROOT / 'benchmarks/references/paired-nest-starter-v1'
    receipt = read(pair / 'receipt.json')
    if sha(pair / 'sbom.json') != receipt['reference_sha256']:
        raise ValueError('Immutable JavaScript reference changed')
    binding_path = ROOT / 'benchmarks/results/no-lock-expanded-v1/paired-nest-starter-v1/binding-proof.json'
    proof = read(binding_path)
    binding = proof['binding']
    sample = prediction['sample']
    observed = archive_binding(ROOT / sample['archive'], binding['index_digest'])
    if (proof.get('unchanged_nonlock_application_tree') is not True or observed != binding
            or binding['config_digest'] != sample['config_digest']
            or binding['platform_manifest_digest'] != sample['platform_digest']):
        raise ValueError('No-lock derivative image is not bound to the controlled reference')
    bom = read(pair / 'sbom.json')
    owner = coord(bom['metadata']['component'])
    expected = {coord(component) for component in all_components(bom) if coord(component)} - {owner}
    actual = projected(read(prediction['analysis'] / 'final.cdx.json'), '/app/', owner)
    direct = graph(bom, owner)
    if not expected or direct is None:
        raise ValueError('Empty or unlabelled reference cannot establish accuracy')
    return {'project': receipt['project'], 'commit': receipt['commit'],
        'components': metrics(actual, expected), 'versions': versions(actual, expected),
        'count_delta': len(actual) - len(expected), 'missing': sorted(expected - actual),
        'extra': sorted(actual - expected), 'direct': metrics(set(), direct),
        'direct_status': 'UNKNOWN_NO_SOURCE_INPUT', 'reference_sha256': sha(pair / 'sbom.json'),
        'no_lock_binding_proof_sha256': sha(binding_path),
        'image_config_binding_verified': True,
        'scope': '/app/ dependencies; primary application excluded; Node/npm and OS retained separately',
        'global_opaque_or_shaded_scope_attested': False,
        'seconds': prediction['run']['elapsed_seconds']}


def previous_views(name, prediction):
    from compare_java_js import coord

    previous = ROOT / ('benchmarks/results/mvp-r112-java-v1/rest/analysis' if name == 'java-rest'
                       else 'benchmarks/results/mvp-js-types-r109-v1/paired-nest-starter-v1/analysis')
    rows = {}
    for view in VIEWS:
        filename = view + '.cdx.json'
        current, prior = read(prediction['analysis'] / filename), read(previous / filename)
        now, before = coordinates(current), coordinates(prior)
        rows[view] = {'current_component_instances': sum(now.values()),
            'previous_component_instances': sum(before.values()),
            'coordinate_multiset_equal': now == before,
            'coordinate_instances_added': list((now - before).elements()),
            'coordinate_instances_removed': list((before - now).elements()),
            'current_sha256': sha(prediction['analysis'] / filename),
            'previous_sha256': sha(previous / filename)}
    # This is a retained semantic regression view, never a rule for selecting truth.
    return {'previous_analysis': previous.relative_to(ROOT).as_posix(), 'views': rows,
            'whole_inventory_including_platform_count_not_tp': True,
            'whole_final_distinct_npm_maven_purls': len({coord(c) for c in
                read(prediction['analysis'] / 'final.cdx.json').get('components', []) if coord(c)})}


def evaluate(root, workspace, output, case_paths=None):
    global ROOT
    ROOT = root
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve completed local API evaluation')
    sys.path.insert(0, str(root / 'src'))
    from sbom_creator.validation import validate_cyclonedx

    predictions, samples_sha = prepare(root, workspace, validate_cyclonedx, case_paths)
    # First reference/packaging-label access occurs strictly after BOTH complete
    # API downloads, every artifact seal, all six schemas and actual image binding.
    results = {'java': java_result(predictions['java-rest']),
               'javascript': javascript_result(predictions['javascript-nest'])}
    for name, row in (('java-rest', results['java']), ('javascript-nest', results['javascript'])):
        row['api_job_id'] = predictions[name]['job_id']
        row['prior_publication_comparison'] = previous_views(name, predictions[name])
    repeated, repeated_samples = prepare(root, workspace, validate_cyclonedx, case_paths)
    if (repeated_samples != samples_sha
            or any(repeated[name]['all_downloaded_artifact_sha256'] != row['all_downloaded_artifact_sha256']
                   or repeated[name]['client_report_sha256'] != row['client_report_sha256']
                   for name, row in predictions.items())):
        raise ValueError('Inputs changed during POST-only evaluation')
    report = {'post_only': True, 'actual_api_predictions': True, 'both_clients_completed_before_oracle': True,
        'source_input': False, 'foreign_project_built': False, 'scanners_called_by_evaluator': False,
        'global_accuracy_or_fresh_blind_acceptance_claim': False,
        'evaluator_sha256': sha(__file__), 'samples_sha256': samples_sha,
        'input_output_seals': {name: {'client_report_sha256': row['client_report_sha256'],
            'artifact_sha256': row['all_downloaded_artifact_sha256']} for name, row in predictions.items()},
        'results': results, 'limitations': [
            'One historically disclosed Java and one JavaScript image, not a new corpus or universal guarantee',
            'Known delivered dependency scope differs from full build/runtime/platform inventory',
            'UNKNOWN reference components count FN; packaging extras remain conservative FP',
            'Image-only direct edges remain UNKNOWN; presence proves neither execution nor directness',
            'Current model-resolution or original TeamCity graph is not inferred']}
    output.mkdir(parents=True, exist_ok=True)
    with (output / 'evaluation.json').open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=ROOT / 'workspace/local-mvp')
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/results/local-mvp-api-v1')
    parser.add_argument('--java-output', type=Path,
                        help='Explicit completed attempt; older failed attempts remain unchanged')
    parser.add_argument('--javascript-output', type=Path)
    args = parser.parse_args()
    paths = {key: value.resolve() for key, value in {
        'java-rest': args.java_output, 'javascript-nest': args.javascript_output}.items() if value}
    report = evaluate(ROOT, args.workspace.resolve(), args.output.resolve(), paths)
    print(json.dumps({language: result['components'] for language, result in report['results'].items()}))


if __name__ == '__main__':
    main()

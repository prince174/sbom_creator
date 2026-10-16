"""Read-only, post-analysis diagnosis of exposed JS ownership/payload gaps.

This is not a classifier or new accuracy run. Existing R106 images and raw scans
are inspected; no code, image, scanner, publisher, labels, or reference changes.
Reference joins are written only after the physical observation report is sealed.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/js-installed-owner-audit-r109-v1'
CASES = ('paired-axios-v2', 'paired-fastify-v1', 'paired-pino-v1', 'paired-nest-starter-v1')
sys.path.insert(0, str(ROOT / 'src'))

from sbom_creator.payload import ImageFiles, _javascript


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')


def installation_slot(manifest, name):
    """Describe conventional Node layout only; no fixture-name blacklist."""
    prefix, sep, relative = manifest.rpartition('/node_modules/')
    if not sep:
        return None
    expected = str(name).strip('/') + '/package.json'
    return {'node_modules_parent': prefix, 'relative': relative,
            'declared_name_matches_slot': relative == expected,
            'canonical_slot': relative == expected}


def reference_coords(bom):
    values = set()

    def add(components):
        for item in components:
            if item.get('purl'):
                from packageurl import PackageURL
                values.add(PackageURL.from_string(item['purl'])._replace(qualifiers=None).to_string())
            add(item.get('components', []))

    add(bom.get('components', []))
    return values


def main():
    if OUTPUT.exists():
        raise FileExistsError('Keep immutable diagnostic namespaces')
    OUTPUT.mkdir(parents=True)
    shutil.copyfile(__file__, OUTPUT / 'executed-runner.py')
    paths, inputs = [], []
    for name in CASES:
        folder = ROOT / 'benchmarks/results/mvp-r106-v1/javascript' / name
        invocation = read(folder / 'invocation.json')
        archive = ROOT / invocation['archive']
        if sha(archive) != invocation['archive_sha256']:
            raise ValueError('Existing immutable image input changed')
        raw = folder / 'analysis/image.syft.json'
        latest = ROOT / 'benchmarks/results/mvp-r108-js-publish-v1' / name / 'analysis'
        files = [folder / 'invocation.json', folder / 'run.json', raw,
                 folder / 'analysis/decisions.json', latest / 'selected.syft.json']
        files.extend(latest / (view + '.cdx.json') for view in ('final', 'os', 'full'))
        inputs.extend(files)
        paths.append((name, folder, raw, latest, archive, invocation))
    write(OUTPUT / 'freeze.json', {
        'mode': 'POST_ANALYSIS_DIAGNOSTIC_ONLY', 'classifier_tuned': False,
        'new_prediction': False, 'fresh_scan': False, 'fresh_physical_inspection': True,
        'project_execution': False, 'source_input': False,
        'oracle_access_before_physical_report': False,
        'runner_sha256': sha(Path(__file__)),
        'code_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p)
                       for p in sorted((ROOT / 'src/sbom_creator').rglob('*.py'))},
        'input_sha256': {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in inputs},
        'archives': {str(a.relative_to(ROOT)).replace('\\', '/'): i['archive_sha256']
                     for _, _, _, _, a, i in paths}})
    rows, started = [], time.monotonic()
    for name, folder, raw, latest, archive, invocation in paths:
        image = read(raw)
        artifacts = [a for a in image['artifacts'] if a.get('foundBy') == 'javascript-package-cataloger']
        roots = {posixpath.dirname(loc['path']) for a in artifacts for loc in a.get('locations', [])}
        source_by_root = {posixpath.dirname(loc['path']): a for a in artifacts
                          for loc in a.get('locations', []) if loc['path'].endswith('/package.json')}
        decisions = {aid: decision for decision in read(folder / 'analysis/decisions.json')
                     for aid in decision.get('image_artifact_ids', [])}
        selected = {a['id'] for a in read(latest / 'selected.syft.json')['artifacts']}
        files = ImageFiles(archive, image)
        result = []
        try:
            for artifact in artifacts:
                for location in artifact.get('locations', []):
                    manifest = location['path']
                    if not manifest.startswith('/app/') or not manifest.endswith('/package.json'):
                        continue
                    raw_manifest = files.read(manifest, 1024 * 1024)
                    if raw_manifest is None:
                        raise ValueError('Expected actual package manifest bytes')
                    data = json.loads(raw_manifest)
                    directory = posixpath.dirname(manifest)
                    parents = [parent for parent in roots if directory.startswith(parent + '/')]
                    parent = max(parents, key=len) if parents else None
                    parent_artifact = source_by_root.get(parent)
                    slot = installation_slot(manifest, data.get('name'))
                    role = ('root_application_manifest' if manifest == '/app/package.json' else
                            'canonical_installed_package_slot' if slot and slot['canonical_slot'] else
                            'embedded_package_manifest_in_parent' if parent else 'unbound_package_location')
                    observed = _javascript(artifact, files, roots)
                    evidence_paths = [observed] if observed else []
                    # Show omitted type-only delivery explicitly, without calling it code.
                    if not observed:
                        evidence_paths.extend(p for p in files.under(directory) if p.endswith('.d.ts')
                                              and not any(p.startswith(other + '/') for other in roots
                                                          if other != directory and other.startswith(directory + '/')))
                    physical = []
                    for target in evidence_paths[:16]:
                        body = files.read(target, 1024 * 1024)
                        physical.append({'path': target, 'size': len(body) if body is not None else None,
                                         'sha256': hashlib.sha256(body).hexdigest() if body is not None else None,
                                         'regular': files.regular(target),
                                         'kind': 'type_declaration' if target.endswith('.d.ts') else 'code_or_resource',
                                         'layer': files.files[target]['location'].get('layerID')})
                    decision = decisions.get(artifact['id'], {})
                    result.append({'artifact_id': artifact['id'], 'purl': artifact.get('purl'),
                        'name': artifact['name'], 'version': artifact['version'], 'manifest': manifest,
                        'manifest_layer': location.get('layerID'), 'manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
                        'manifest_size': len(raw_manifest), 'manifest_identity_matches':
                            (data.get('name') == artifact['name'] and data.get('version') == artifact['version']),
                        'manifest_fields': {key: data[key] for key in
                            ('name', 'version', 'main', 'module', 'types', 'typings', 'exports', 'private', 'workspaces') if key in data},
                        'root_dependency_names': sorted(data.get('dependencies', {})),
                        'role_by_layout_only': role, 'installation_slot': slot,
                        'nearest_parent_manifest': parent + '/package.json' if parent else None,
                        'nearest_parent_purl': parent_artifact.get('purl') if parent_artifact else None,
                        'legacy_payload_witness': observed, 'physical_files': physical,
                        'current_runtime_decision': decision.get('decision'),
                        'current_runtime_reason': decision.get('review_reason'),
                        'selected_in_r108': artifact['id'] in selected})
        finally:
            files.close()
        rows.append({'pair': name, 'image': invocation['image'], 'archive_sha256': invocation['archive_sha256'],
                     'app_manifest_observations': result})
    physical = {'post_analysis_diagnostic': True, 'oracle_opened': False,
                'component_proofs_are_not_runtime_execution': True,
                'elapsed_seconds': time.monotonic() - started, 'rows': rows}
    write(OUTPUT / 'physical-observations.json', physical)
    write(OUTPUT / 'physical-observations-complete.json', {'oracle_opened': False,
        'sha256': sha(OUTPUT / 'physical-observations.json'), 'cases': list(CASES)})
    # Post-only reference joins begin here. They never select a classifier rule.
    comparison = []
    for row in rows:
        reference = ROOT / 'benchmarks/references' / row['pair'] / 'sbom.json'
        expected = reference_coords(read(reference))
        observations = []
        for observation in row['app_manifest_observations']:
            from packageurl import PackageURL
            purl = PackageURL.from_string(observation['purl'])._replace(qualifiers=None).to_string()
            observations.append({'artifact_id': observation['artifact_id'], 'purl': purl,
                'manifest': observation['manifest'], 'in_build_reference_components': purl in expected,
                'selected_in_runtime_final': observation['selected_in_r108'],
                'role_by_layout_only': observation['role_by_layout_only'],
                'has_actual_file_bytes': any(f['sha256'] for f in observation['physical_files']),
                'legacy_payload_witness': observation['legacy_payload_witness']})
        comparison.append({'pair': row['pair'], 'reference_sha256': sha(reference), 'observations': observations})
    write(OUTPUT / 'post-reference-diagnostic.json', {'post_analysis_only': True,
        'new_accuracy_measurement': False, 'new_classifier': False,
        'physical_report_sha256': sha(OUTPUT / 'physical-observations.json'), 'rows': comparison})
    print(json.dumps({'cases': len(rows), 'observations': sum(len(r['app_manifest_observations']) for r in rows),
                      'seconds': physical['elapsed_seconds']}))


if __name__ == '__main__':
    main()

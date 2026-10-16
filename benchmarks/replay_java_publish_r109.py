"""R109 Java publisher regression over sealed R108 prepared image evidence.

No scanner, source resolver, physical reader, reference or evaluator is called.
The changed global JavaScript policy must preserve the Java v7 publications.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

from replay_js_publish_r107 import coordinates, selected_ids, sha
from run import ROOT, atomic_json


def read(path):
    return json.loads(Path(path).read_bytes())


def forbidden(*_args, **_kwargs):
    raise AssertionError('Publisher-only regression forbids acquisition, scanners and source resolution')


def main():
    output = ROOT / 'benchmarks/results/mvp-r109-java-publish-v1'
    if output.exists():
        raise FileExistsError('Preserve completed and attempted publisher regressions')
    previous = ROOT / 'benchmarks/results/mvp-r108-v1/java'
    names = ('microservices', 'boot', 'javalin', 'dropwizard')
    js_freeze_path = ROOT / 'benchmarks/results/mvp-js-types-r109-v1/freeze.json'
    js_freeze = read(js_freeze_path)
    snapshot = output / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    code_hashes = {path.relative_to(snapshot).as_posix(): sha(path)
                   for path in sorted(snapshot.rglob('*')) if path.is_file()}
    if code_hashes != js_freeze['code_sha256'] or len(code_hashes) != 47:
        raise ValueError('Current exact 47 files differ from the frozen R109 JavaScript candidate')
    shutil.copyfile(__file__, output / 'executed-runner.py')
    helper = ROOT / 'benchmarks/replay_js_publish_r107.py'
    shutil.copyfile(helper, output / 'executed-coordinate-helper.py')
    syft = ROOT / '.tools/syft/syft.exe'
    paths = [previous / name / 'analysis' / filename for name in names for filename in
             ('source.syft.json', 'image.syft.json', 'provenance.json', 'selected.syft.json',
              'final.cdx.json', 'os.cdx.json', 'full.cdx.json', 'summary.json')]
    paths.append(js_freeze_path)
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'fresh_scans': False,
        'fresh_physical_reads': False, 'source_input': False, 'project_execution': False,
        'java_nested_windows': True, 'java_archive_components': True,
        'production_default_changed': False, 'new_accuracy_measurement': False,
        'mode': 'actual publisher over four cached R108 prepared Java catalogs and sealed physical/archive evidence',
        'runner_sha256': sha(Path(__file__)), 'coordinate_helper_sha256': sha(helper),
        'syft_converter_sha256': sha(syft), 'code_sha256': code_hashes,
        'code_equals_frozen_r109_js_candidate': True,
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in paths},
        'baselines': [(previous / name / 'analysis').relative_to(ROOT).as_posix() for name in names]})
    sys.path.insert(0, str(snapshot))
    from sbom_creator import pipeline
    from sbom_creator.acquire import Settings
    from sbom_creator.core import rules_assessor
    from sbom_creator.validation import validate_cyclonedx

    if not Path(pipeline.__file__).is_relative_to(snapshot):
        raise ValueError('Publisher did not import its frozen source snapshot')
    for name in ('scan_image', 'scan_source', 'checkout', 'resolve_java'):
        setattr(pipeline, name, forbidden)
    settings = Settings(syft_binary=str(syft), java_backend='disabled',
                        java_nested_windows=True, java_archive_components=True)
    reports, started = [], time.monotonic()
    for name in names:
        baseline, target = previous / name / 'analysis', output / name
        before = time.monotonic()
        source, image, provenance = (read(baseline / filename) for filename in
                                     ('source.syft.json', 'image.syft.json', 'provenance.json'))
        if source['artifacts'] or provenance.get('request', {}).get('repository_url') is not None:
            raise ValueError('Cached baseline must remain image-only with empty source')
        if provenance['image'].get('java_reader_policy') != 'verified-java-archive-component-v1':
            raise ValueError('The R108 prepared archive evidence policy is required')
        if not provenance['image'].get('identity_binding_envelope'):
            raise ValueError('Prepared in-process identity evidence is missing')
        summary = pipeline.publish_catalogs(source, image, target / 'analysis', settings,
                                            rules_assessor, provenance)
        if summary['policy_version'] != 'image-delivered-archive-v7':
            raise ValueError('Java v7 policy unexpectedly changed')
        views = {}
        for view in ('final', 'os', 'full'):
            path = target / 'analysis' / (view + '.cdx.json')
            actual = read(path)
            validate_cyclonedx(actual)
            expected = read(baseline / (view + '.cdx.json'))
            if coordinates(actual) != coordinates(expected):
                raise ValueError('R109 Java publisher component-coordinate regression')
            views[view] = {'coordinates_equal': True,
                           'component_count': len(actual.get('components', [])),
                           'cyclonedx_schema_valid': True, 'sha256': sha(path)}
        if selected_ids(read(target / 'analysis/selected.syft.json')) != selected_ids(read(baseline / 'selected.syft.json')):
            raise ValueError('R109 Java publisher selected-artifact regression')
        report = {'name': name, 'status': 'passed', 'oracle_read': False,
            'fresh_scans': False, 'fresh_physical_reads': False, 'source_input': False,
            'policy_version': summary['policy_version'], 'views': views,
            'selected_artifact_ids_equal': True, 'summary': summary,
            'elapsed_seconds': time.monotonic() - before,
            'baseline': baseline.relative_to(ROOT).as_posix(), 'new_accuracy_measurement': False}
        atomic_json(target / 'run.json', report)
        reports.append(report)
        print(name, 'R109 cached publisher Java v7 parity passed', flush=True)
    freeze = read(output / 'freeze.json')
    for relative, digest in freeze['input_sha256'].items():
        if sha(ROOT / relative) != digest:
            raise ValueError('Frozen cached input changed during R109 Java regression')
    for relative, digest in freeze['code_sha256'].items():
        if sha(snapshot / relative) != digest or sha(ROOT / 'src' / relative) != digest:
            raise ValueError('Executed candidate changed during publisher regression')
    atomic_json(output / 'report.json', {'status': 'passed', 'cases': reports,
        'oracle_read': False, 'fresh_scans': False, 'fresh_physical_reads': False,
        'source_input': False, 'project_execution': False,
        'java_nested_windows': True, 'java_archive_components': True,
        'production_default_changed': False, 'new_accuracy_measurement': False,
        'views_equal': 12, 'selected_artifact_id_sets_equal': 4,
        'java_policy_version_unchanged': 'image-delivered-archive-v7',
        'code_equals_frozen_r109_js_candidate': True, 'source_file_hashes_equal': 47,
        'elapsed_seconds': time.monotonic() - started,
        'freeze_sha256': sha(output / 'freeze.json')})


if __name__ == '__main__':
    main()

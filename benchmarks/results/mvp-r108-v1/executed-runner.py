"""Freeze service code and predict from cached engines plus fresh physical bytes.

Only image inputs and producer inventories are used. Build/reference labels are
reserved for a separate evaluator after all four Java publications finish.
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json
from run_mvp_r106 import input_cases, sha


def read(path):
    return json.loads(Path(path).read_bytes())


def main():
    output = ROOT / 'benchmarks/results/mvp-r108-v1'
    if output.exists():
        raise FileExistsError('Preserve attempts')
    cases = [case for case in input_cases() if case['language'] == 'java']
    prior = ROOT / 'benchmarks/results/mvp-r107-v1/java'
    snapshot = output / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output / 'executed-runner.py')
    database = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache/java-db/trivy-java.db'
    metadata = database.with_name('metadata.json')
    inputs = {p.relative_to(ROOT).as_posix(): sha(p) for p in (database, metadata)}
    database_sha256 = inputs[database.relative_to(ROOT).as_posix()]
    for case in cases:
        paths = [case['archive']] + [prior / case['name'] / 'analysis' / name for name in
            ('image-original.syft.json', 'image-peer.cdx.json', 'source.syft.json', 'provenance.json')]
        inputs.update({p.relative_to(ROOT).as_posix(): sha(p) for p in paths})
    syft = ROOT / '.tools/syft/syft.exe'
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'fresh_scanners': False,
        'fresh_physical_reads': True, 'actual_service_publisher': True,
        'mode': 'image-only experimental verified archive components; observed code payload unchanged',
        'java_nested_windows': True, 'java_archive_components': True, 'cases': [case['name'] for case in cases],
        'syft_sha256': sha(syft),
        'code_sha256': {p.relative_to(snapshot).as_posix(): sha(p)
                        for p in sorted(snapshot.rglob('*')) if p.is_file()},
        'input_sha256': inputs})
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java.runtime import corroborate
    from sbom_creator.pipeline import publish_catalogs, rules_assessor

    if not Path(sys.modules['sbom_creator.image_java.runtime'].__file__).is_relative_to(snapshot):
        raise ValueError('Snapshot was not imported')
    completed, failed = [], []
    for case in cases:
        name = case['name']
        target = output / 'java' / name
        previous = prior / name / 'analysis'
        started = time.monotonic()
        atomic_json(target / 'invocation.json', {'oracle_read': False, 'source_input': False,
            'fresh_scanners': False, 'fresh_physical_reads': True,
            'image': case['image'], 'archive': case['archive'].relative_to(ROOT).as_posix(),
            'java_nested_windows': True, 'java_archive_components': True, 'producer_inventory': previous.relative_to(ROOT).as_posix()})
        try:
            image, peer = read(previous / 'image-original.syft.json'), read(previous / 'image-peer.cdx.json')
            temporary = ROOT / 'benchmarks/.work/mvp-r108-physical'
            temporary.mkdir(parents=True, exist_ok=True)
            adapted, physical, envelope, audit = corroborate(image, case['archive'], peer,
                temporary=temporary, nested_windows=True, archive_components=True,
                java_database=database, database_sha256=database_sha256)
            provenance = copy.deepcopy(read(previous / 'provenance.json'))
            provenance['image'].update(payload_evidence=physical, identity_binding_envelope=envelope,
                java_reader_policy='verified-java-archive-component-v1',
                _artifacts={'image-original.syft.json': image, 'image-peer.cdx.json': peer,
                            'image-identity-audit.json': audit})
            summary = publish_catalogs(read(previous / 'source.syft.json'), adapted, target / 'analysis',
                Settings(syft_binary=str(syft), java_nested_windows=True, java_archive_components=True), rules_assessor, provenance)
            atomic_json(target / 'run.json', {'status': 'completed', 'oracle_read': False,
                'elapsed_seconds': time.monotonic() - started, 'summary': summary,
                'fresh_scanners': False, 'fresh_physical_reads': True,
                'timing': 'cached producer inventories; fresh image physical evidence and actual publisher'})
            completed.append(name)
            print(name, 'completed', summary['final_count'], flush=True)
        except Exception as error:  # noqa: BLE001 -- retain safe negative outcomes
            failed.append(name)
            atomic_json(target / 'run.json', {'status': 'FAILED', 'oracle_read': False,
                'elapsed_seconds': time.monotonic() - started, 'error_type': type(error).__name__,
                'error_stage': getattr(error, 'stage', None)})
            print(name, 'FAILED', type(error).__name__, flush=True)
    atomic_json(output / 'predictions-complete.json', {'oracle_read': False,
        'cases': [case['name'] for case in cases], 'completed': completed, 'failed': failed,
        'freeze_sha256': sha(output / 'freeze.json')})


if __name__ == '__main__':
    main()

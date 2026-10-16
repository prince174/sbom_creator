"""Freeze selector wiring, replay physical bytes and publish three real views.

No scanners or build references are inputs. Compare against completed predictions,
not an oracle. The measured R106 reader must remain opt-in and byte-identical.
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from run import ROOT, atomic_json


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def views(path):
    from collections import Counter

    from compare_java_js import all_components, coord
    return {view: Counter(coord(c) for c in all_components(read(path / (view + '.cdx.json'))) if coord(c))
            for view in ('final', 'os', 'full')}


def main():
    output = ROOT / 'benchmarks/results/mvp-r106-selector-parity-v1'
    if output.exists():
        raise FileExistsError('Preserve the selector replay')
    original = ROOT / 'benchmarks/results/mvp-r106-v1'
    prior_algorithm = original / 'java/executed-source/src/sbom_creator/image_java/seekable_jar_evidence.py'
    algorithm = ROOT / 'src/sbom_creator/image_java/stored_jar_evidence.py'
    if algorithm.read_bytes() != prior_algorithm.read_bytes():
        raise ValueError('The opt-in algorithm differs from the measured experimental reader')
    cases = [('experimental-microservices', 'microservices', True,
              original / 'java/microservices/analysis'),
             ('default-boot', 'boot', False,
              ROOT / 'benchmarks/results/mvp-image-r105-serial-boot/boot/analysis')]
    snapshot = output / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', snapshot / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output / 'executed-runner.py')
    inputs, resolved = {}, []
    for name, case, enabled, expected in cases:
        current = original / 'java' / case
        archive = ROOT / read(current / 'invocation.json')['archive']
        paths = [current / 'analysis' / file for file in ('image-original.syft.json', 'image-peer.cdx.json',
                                                         'source.syft.json', 'provenance.json')]
        paths += [archive]
        paths += [expected / (view + '.cdx.json') for view in ('final', 'os', 'full')]
        inputs.update({p.relative_to(ROOT).as_posix(): sha(p) for p in paths})
        resolved.append((name, case, enabled, expected, archive))
    syft = ROOT / '.tools/syft/syft.exe'
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'fresh_scanners': False,
        'fresh_physical_reads': True, 'default_nested_windows': False,
        'opt_in_algorithm_exact_bytes_sha256': sha(algorithm), 'syft_sha256': sha(syft),
        'code_sha256': {p.relative_to(snapshot).as_posix(): sha(p)
                        for p in sorted(snapshot.rglob('*')) if p.is_file()}, 'input_sha256': inputs})
    sys.path.insert(0, str(snapshot))
    from sbom_creator.acquire import Settings
    from sbom_creator.image_java.runtime import corroborate
    from sbom_creator.pipeline import publish_catalogs, rules_assessor

    if Settings().java_nested_windows is not False:
        raise ValueError('The experimental reader became the default')
    reports = {}
    for name, case, enabled, expected, archive in resolved:
        current = original / 'java' / case / 'analysis'
        image = read(current / 'image-original.syft.json')
        peer = read(current / 'image-peer.cdx.json')
        started = time.monotonic()
        temporary = ROOT / 'benchmarks/.work/mvp-r106-selector-temporary'
        temporary.mkdir(parents=True, exist_ok=True)
        adapted, physical, envelope, audit = corroborate(image, archive, peer,
            temporary=temporary, nested_windows=enabled)
        provenance = copy.deepcopy(read(current / 'provenance.json'))
        provenance['image'].update(payload_evidence=physical, identity_binding_envelope=envelope,
            java_reader_policy=('stored-nested-windows-full-crc-bounded-range-cache-v1' if enabled
                                else 'seekable-content-verification-v4'),
            _artifacts={'image-original.syft.json': image, 'image-peer.cdx.json': peer,
                        'image-identity-audit.json': audit})
        target = output / name / 'analysis'
        summary = publish_catalogs(read(current / 'source.syft.json'), adapted, target,
            Settings(syft_binary=str(syft), java_nested_windows=enabled), rules_assessor, provenance)
        expected_policy = 'image-identity-payload-v5' if enabled else 'image-identity-payload-v4'
        if summary['policy_version'] != expected_policy or views(target) != views(expected):
            raise ValueError('Selector mode or final/os/full coordinates differ')
        old_ids = {a['id'] for a in read(expected / 'selected.syft.json')['artifacts']}
        new_ids = {a['id'] for a in read(target / 'selected.syft.json')['artifacts']}
        if old_ids != new_ids:
            raise ValueError('Selected artifact identity sets differ')
        if enabled and (adapted != read(current / 'image.syft.json')
                        or physical != read(current / 'provenance.json')['image']['payload_evidence']
                        or audit != read(current / 'image-identity-audit.json')):
            raise ValueError('Opt-in physical evidence/catalog/audit differs from the measured run')
        reports[name] = {'java_nested_windows': enabled, 'policy_version': expected_policy,
            'coordinate_multisets_equal_all_three': True, 'selected_ids_equal': True,
            'opt_in_facts_exact': True if enabled else None,
            'elapsed_seconds': time.monotonic() - started, 'summary': summary,
            'jar_resources': audit['jar_resources'], 'oracle_read': False,
            'timing': 'cached scanner catalogs; fresh physical reads and actual Syft conversion'}
        atomic_json(output / name / 'run.json', reports[name])
        print(name, 'parity passed', flush=True)
    atomic_json(output / 'report.json', {'status': 'passed', 'oracle_read': False,
        'default_reader_preserved': True, 'experimental_opt_in_only': True, 'cases': reports})


if __name__ == '__main__':
    main()

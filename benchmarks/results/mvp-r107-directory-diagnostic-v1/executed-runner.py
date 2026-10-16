"""Observe the frozen R106 reader's actual guard failures, without oracle inputs."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from run import ROOT, atomic_json


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    output = ROOT / 'benchmarks/results/mvp-r107-directory-diagnostic-v1'
    if output.exists():
        raise FileExistsError('Preserve diagnostic attempts')
    prior = ROOT / 'benchmarks/results/mvp-r106-v1/java/microservices/analysis'
    archive = ROOT / 'benchmarks/.work/paired-petclinic-microservices-r104/image.tar'
    sources = output / 'executed-source'
    shutil.copytree(ROOT / 'src/sbom_creator', sources / 'sbom_creator',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(__file__, output / 'executed-runner.py')
    inputs = [archive] + [prior / name for name in
                         ('image-original.syft.json', 'image-peer.cdx.json', 'image.syft.json', 'provenance.json')]
    atomic_json(output / 'freeze.json', {'oracle_read': False, 'fresh_scanners': False,
        'fresh_physical_reads': True, 'classifier_changed': False,
        'code_sha256': {p.relative_to(sources).as_posix(): sha(p)
                        for p in sorted(sources.rglob('*')) if p.is_file()},
        'input_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in inputs}})
    sys.path.insert(0, str(sources))
    from sbom_creator.core import checksum
    from sbom_creator.image_java import runtime
    from sbom_creator.image_java.bounded_jar_evidence import BudgetExceeded

    counts, maxima = Counter(), {'fingerprints': 0, 'directory_bytes': 0, 'entries': 0}
    original = runtime.StoredJarFiles

    class DiagnosticReader(original):
        def archive(self, key, stream):
            try:
                return super().archive(key, stream)
            except BudgetExceeded as error:
                # Only our fixed internal guard labels are recorded, never an
                # exception string/path derived from hostile image content.
                if str(error) == 'Unique ZIP directory budget' and len(self.indexes) >= 256:
                    counts['zip_fingerprint_capacity_256'] += 1
                else:
                    counts['other_budget'] += 1
                maxima['fingerprints'] = max(maxima['fingerprints'], len(self.indexes))
                maxima['directory_bytes'] = max(maxima['directory_bytes'], self.stats['index_bytes'])
                maxima['entries'] = max(maxima['entries'], self.stats['zip_entries'])
                raise

    image = json.loads((prior / 'image-original.syft.json').read_bytes())
    peer = json.loads((prior / 'image-peer.cdx.json').read_bytes())
    temporary = ROOT / 'benchmarks/.work/r107-directory-diagnostic'
    temporary.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with patch.object(runtime, 'StoredJarFiles', DiagnosticReader):
        adapted, physical, _, audit = runtime.corroborate(image, archive, peer,
            temporary=temporary, nested_windows=True)
    previous_physical = json.loads((prior / 'provenance.json').read_bytes())['image']['payload_evidence']
    if adapted != json.loads((prior / 'image.syft.json').read_bytes()) or physical != previous_physical:
        raise ValueError('Diagnostic changed predictions')
    atomic_json(output / 'report.json', {'status': 'passed', 'oracle_read': False,
        'new_accuracy_measurement': False, 'elapsed_seconds': time.monotonic() - started,
        'predictions_exactly_equal_r106': True, 'actual_failed_guard_counts': dict(counts),
        'ledger_at_rejection': maxima, 'adapted_catalog_sha256': checksum(adapted),
        'physical_evidence_sha256': checksum(physical), 'jar_resources': audit['jar_resources'],
        'layer_resources': audit['layer_resources']})
    print(json.dumps({'counts': counts, 'ledger': maxima}), flush=True)


if __name__ == '__main__':
    main()

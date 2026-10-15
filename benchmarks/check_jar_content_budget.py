"""Development-only experiment: metadata scan plus bounded local archive evidence.

This is NOT a registry-compatible runtime replacement. Never reads an oracle
before prediction. Existing output/read budgets remain unchanged.
"""
import json
import time
from unittest.mock import patch

from run import ROOT, atomic_json

from sbom_creator import payload, scanner
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

MAX_TOTAL_READ = 128 * 1024 * 1024


class BudgetFiles(payload.ImageFiles):
    stats = None

    def read(self, name, limit=payload.MAX_READ):
        limit = min(limit, payload.MAX_READ)
        entry = self.files.get(payload.path(name), {})
        size = entry.get('metadata', {}).get('size', 0)
        if size > limit or size > MAX_TOTAL_READ - self.stats['read_bytes']:
            self.stats['budget_rejections'] += 1
            return None
        data = super().read(name, limit)
        if data is not None:
            self.stats['read_bytes'] += len(data)
            self.stats['read_calls'] += 1
        return data


def main():
    pair = 'paired-javalin-reactor-v1'
    work = ROOT/'benchmarks/.work'/pair
    output = ROOT/'benchmarks/results/jar-content-budget-v1'
    analysis = work/'analysis-metadata-archive-v1'
    if output.exists() or analysis.exists():
        raise FileExistsError('Experiment already attempted; preserve evidence')
    stats = {'read_bytes': 0, 'read_calls': 0, 'budget_rejections': 0}
    config = scanner.IMAGE_CONFIG
    for suffix in ('jar', 'war', 'ear', 'zip', 'hpi', 'jpi', 'nar', 'jmod'):
        config = config.replace('      - "**/*.' + suffix + '"\n', '')
    assert '**/*.jar' not in config and 'selection: all' in config
    original_collect = payload.collect

    def collect(document):
        with patch.object(payload, 'ImageFiles', BudgetFiles):
            return original_collect(document, work/'image.tar')

    started = time.monotonic()
    with patch.object(BudgetFiles, 'stats', stats), patch.object(scanner, 'IMAGE_CONFIG', config), patch.object(scanner, 'collect_payload', collect):
        analyze_local(work/'src', 'docker.io/sbom-creator-benchmark/paired-javalin-reactor:v1', analysis,
                      Settings(syft_binary=str(ROOT/'.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(work/'image.tar')))
    elapsed = time.monotonic() - started
    for view in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis/(view+'.cdx.json')).read_bytes()))
    # Oracle access happens only after the prediction and all three outputs.
    receipt = json.loads((ROOT/'benchmarks/references'/pair/'receipt.json').read_bytes())
    provenance = json.loads((analysis/'provenance.json').read_bytes())
    atomic_json(output/'report.json', {'pair': pair, 'development_only': True, 'runtime_changed': False,
                'production_registry_compatible': False, 'status': 'ANALYSIS_COMPLETED',
                'baseline': receipt['analysis_status'], 'elapsed_seconds': elapsed,
                'archive_read_budget': MAX_TOTAL_READ, 'per_read_limit': payload.MAX_READ,
                'output_limit': Settings().max_sbom_bytes, 'archive_reads': stats,
                'catalog_bytes': (analysis/'image.syft.json').stat().st_size,
                'three_views_schema_valid': True, 'provenance': provenance,
                'limitation': 'Local original archive required. Does not solve registry acquisition, large outer JARs, identity or owner/direct classification. No accuracy claim or holdout tuning.'})
    print(json.dumps({'elapsed': elapsed, 'reads': stats, 'catalog_bytes': (analysis/'image.syft.json').stat().st_size}))


if __name__ == '__main__':
    main()

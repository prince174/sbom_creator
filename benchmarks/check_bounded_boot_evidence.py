"""Development Boot replay with bounded disk-backed evidence; oracle only last."""
import hashlib
import json
import shutil
import subprocess
import time
from unittest.mock import patch

import bounded_jar_evidence as candidate
from compare_java_js import all_components, coord
from run import ROOT, atomic_json
from score_project_components import metrics

from sbom_creator import payload, scanner
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx


def main():
    pair = 'paired-spring-petclinic-v1'
    work = ROOT / 'benchmarks/.work' / pair
    output = ROOT / 'benchmarks/results/bounded-boot-evidence-v2'
    analysis = work / 'analysis-bounded-jar-v2'
    if output.exists() or analysis.exists():
        raise FileExistsError('Preserve attempted run')
    selected = next(row for row in json.loads((ROOT / 'benchmarks/java-js-expanded-v1.json').read_bytes())['repositories']
                    if row['id'] == 'java-spring-petclinic')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(work / 'src'), *args], text=True).strip()
    assert git('rev-parse', 'HEAD') == selected['commit'] and not git('status', '--porcelain')
    atomic_json(output / 'candidate-freeze.json', {'development_only': True,
                'runtime_changed': False, 'commit': selected['commit'],
                'code_sha256': hashlib.sha256((ROOT / 'benchmarks/bounded_jar_evidence.py').read_bytes()).hexdigest(),
                'limits': {key: getattr(candidate, key) for key in ('CHUNK', 'MAX_OUTER', 'MAX_NESTED', 'MAX_COPY',
                                                                 'MAX_INDEX', 'MAX_INDEX_TOTAL', 'MAX_ENTRIES', 'MAX_LAYER_BYTES', 'MAX_RATIO', 'MAX_DEPTH')}})
    original_collect = payload.collect
    readers = []
    evidence_rows = {}

    def make_files(archive, document):
        files = candidate.JarFiles(archive, document)
        readers.append(files)
        return files

    def java(artifact, files):
        try:
            return files.witness(artifact)
        except ValueError:
            files.stats['rejections'] += 1
            raise

    def collect(document):
        with patch.object(payload, 'ImageFiles', make_files), patch.object(payload, '_java', java):
            rows = original_collect(document, work / 'image.tar')
        for row in rows.values():
            row['method'] = 'experimental-bounded-disk-and-zip-index-v2'
        evidence_rows.update(rows)
        return rows

    config = scanner.IMAGE_CONFIG
    for suffix in ('jar', 'war', 'ear', 'zip', 'hpi', 'jpi', 'nar', 'jmod'):
        config = config.replace('      - "**/*.' + suffix + '"\n', '')
    started = time.monotonic()
    with patch.object(scanner, 'IMAGE_CONFIG', config), patch.object(scanner, 'collect_payload', collect):
        analyze_local(work / 'src', 'docker.io/sbom-creator-benchmark/paired-spring-petclinic:v1', analysis,
                      Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',),
                               image_archive=str(work / 'image.tar')))
    elapsed = time.monotonic() - started
    for view in ('final', 'os', 'full'):
        validate_cyclonedx(json.loads((analysis / (view + '.cdx.json')).read_bytes()))
        shutil.copyfile(analysis / (view + '.cdx.json'), output / (view + '.cdx.json'))
    atomic_json(output / 'witnesses.json', evidence_rows)
    # Only after prediction and three complete outputs: open evaluation-only labels.
    labels = json.loads((ROOT / 'benchmarks/results/boot-packaging-labels-v3/report.json').read_bytes())
    assert labels['commit'] == selected['commit']
    expected = set(labels['packaged'])
    reference = json.loads((ROOT / 'benchmarks/references' / pair / 'sbom.json').read_bytes())
    owner = coord(reference['metadata']['component'])

    def components(directory):
        document = json.loads((directory / 'final.cdx.json').read_bytes())
        return {coord(component) for component in all_components(document) if coord(component) and any(
            prop.get('name', '').startswith('syft:location:') and prop.get('name', '').endswith(':path')
            and prop.get('value', '').startswith('/application/') for prop in component.get('properties', []))} - {owner}
    actual = components(analysis)
    baseline = components(work / 'analysis')
    atomic_json(output / 'report.json', {'project': selected['id'], 'partition': 'disclosed_development',
                'runtime_changed': False, 'elapsed_seconds': elapsed, 'three_views_schema_valid': True,
                'baseline_final_components': metrics(baseline, expected),
                'candidate_final_components': metrics(actual, expected),
                'missing': sorted(expected - actual), 'extra': sorted(actual - expected),
                'candidate_readers': [reader.stats for reader in readers],
                'catalog_bytes': (analysis / 'image.syft.json').stat().st_size,
                'summary': json.loads((analysis / 'summary.json').read_bytes()),
                'limitations': ['Development prototype, not runtime integration or fresh control',
                               'Some class/resource bytes, not runtime execution or direct-edge proof',
                               'Syft coordinates unchanged; Trivy identity/source-owner bridge not integrated',
                               'ZIP64, compressed outer tar and archives over declared budgets unsupported',
                               'No peak RSS claim; disk/file count/time hardening needs further review']})
    print(json.dumps({'baseline': metrics(baseline, expected), 'candidate': metrics(actual, expected),
                      'readers': [reader.stats for reader in readers], 'elapsed_seconds': elapsed}))


if __name__ == '__main__':
    main()

"""Disclosed resource-control replay; reference data is never read here."""
import hashlib
import json
import shutil
import time
from unittest.mock import patch

import bounded_jar_evidence as frozen
import trivy_only_payload
from cached_jar_evidence import JarFiles
from run import ROOT, atomic_json

from sbom_creator import core, payload, scanner
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local, publish_catalogs, rules_assessor
from sbom_creator.validation import validate_cyclonedx


def main():
    work = ROOT / 'benchmarks/.work/paired-dropwizard-reactor-v1'
    output = ROOT / 'benchmarks/results/cached-dropwizard-evidence-v3'
    prior = ROOT / 'benchmarks/results/dropwizard-frozen-control-v1'
    if output.exists():
        raise FileExistsError('Preserve previous attempt')
    freeze = json.loads((prior / 'candidate-freeze.json').read_bytes())
    for name, digest in freeze['predictors'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen classifier changed')
    atomic_json(output / 'candidate-freeze.json', {
        'partition': 'disclosed_resource_development', 'runtime_changed': False, 'oracle_read': False,
        'code_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
            'benchmarks/cached_jar_evidence.py', 'benchmarks/replay_cached_dropwizard.py')},
        'frozen_predictors': freeze['predictors'], 'limits_increased': False,
        'input_image_sha256': image_hash(work / 'image.tar')})
    readers, witnesses = [], {}
    original_collect = payload.collect

    def make_files(archive, document):
        files = JarFiles(archive, document)
        readers.append(files)
        return files

    def collect(document):
        with patch.object(payload, 'ImageFiles', make_files), patch.object(
                payload, '_java', lambda artifact, files: files.witness(artifact)):
            rows = original_collect(document, work / 'image.tar')
        witnesses.update(rows)
        return rows

    configuration = scanner.IMAGE_CONFIG
    for suffix in ('jar', 'war', 'ear', 'zip', 'hpi', 'jpi', 'nar', 'jmod'):
        configuration = configuration.replace('      - "**/*.' + suffix + '"\n', '')
    started = time.monotonic()
    settings = Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'),
                        registry_hosts=('docker.io',), image_archive=str(work / 'image.tar'))
    analysis = work / 'analysis-cached-evidence-input-v3'
    with patch.object(scanner, 'IMAGE_CONFIG', configuration), patch.object(scanner, 'collect_payload', collect):
        analyze_local(work / 'src', 'docker.io/sbom-creator-benchmark/paired-dropwizard:v1', analysis, settings)
    image = json.loads((analysis / 'image.syft.json').read_bytes())
    source = json.loads((analysis / 'source.syft.json').read_bytes())
    peer = json.loads((prior / 'prediction-v1/image/sbom.json').read_bytes())
    with patch.object(trivy_only_payload, 'JarFiles', JarFiles):
        adapted, evidence, audit = trivy_only_payload.supplement(image, peer, witnesses, work / 'image.tar')
    atomic_json(output / 'witnesses.json', witnesses)
    atomic_json(output / 'supplement.json', audit)
    provenance = json.loads((analysis / 'provenance.json').read_bytes())
    provenance['image']['payload_evidence'] = evidence
    final = work / 'analysis-cached-evidence-final-v3'
    producer = trivy_only_payload.CATALOGER
    with patch.dict(core._DIRECT_CATALOGERS, {producer: 'archive_metadata'}), patch.object(
            core, 'PAYLOAD_CATALOGERS', core.PAYLOAD_CATALOGERS | {producer}), patch.object(
            core, 'RULES_POLICY_VERSION', 'experimental-trivy-only-payload-v1'):
        summary = publish_catalogs(source, adapted, final, settings, rules_assessor, provenance)
    for view in ('final', 'os', 'full'):
        path = final / (view + '.cdx.json')
        validate_cyclonedx(json.loads(path.read_bytes()))
        shutil.copyfile(path, output / path.name)
    atomic_json(output / 'run.json', {'oracle_read': False, 'runtime_changed': False,
                'seconds': time.monotonic() - started, 'summary': summary,
                'readers': [r.stats for r in readers], 'three_views_valid': True,
                'limits': {key: getattr(frozen, key) for key in ('MAX_COPY', 'MAX_LAYER_BYTES', 'MAX_INDEX_TOTAL')},
                'source_owner_graph': 'FAILED_PREVIOUS_TIMEOUT_NOT_RETRIED', 'peak_rss_bytes': None})
    print(json.dumps({'seconds': time.monotonic() - started, 'readers': [r.stats for r in readers]}))


def image_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


if __name__ == '__main__':
    main()

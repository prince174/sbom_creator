"""Input adapter for the frozen R98/R92 predictors; never opens build labels."""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import time
from unittest.mock import patch

from http_integration import command
from run import ROOT, atomic_json
from trivy_only_payload import CATALOGER, supplement
from trivy_optional_projection import project_pom
from trivy_pom_graph import extract

from sbom_creator import core, payload, scanner
from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local, publish_catalogs, rules_assessor
from sbom_creator.validation import validate_cyclonedx


def main(continue_image=False):
    work = ROOT / 'benchmarks/.work/paired-dropwizard-reactor-v1'
    output = ROOT / 'benchmarks/results/dropwizard-frozen-control-v1'
    frozen = json.loads((output / 'candidate-freeze.json').read_bytes())
    for name, digest in frozen['predictors'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen predictor changed')
    if hashlib.sha256((ROOT / 'src/sbom_creator/core.py').read_bytes()).hexdigest() != frozen['core_sha256']:
        raise ValueError('Frozen core changed')
    source = work / 'src'
    if (command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != frozen['commit'] or
            command(['git', '-C', str(source), 'status', '--porcelain'])):
        raise ValueError('Source differs')
    if not (work / 'image.tar').exists():
        raise FileNotFoundError('Wait for existing build, never duplicate it')
    prediction = output / 'prediction-v1'
    if continue_image:
        if (not (prediction / 'failure.json').exists() or
                json.loads((prediction / 'image/run.json').read_bytes())['exit_code'] != 0 or
                (prediction / 'witnesses.json').exists() or
                (prediction / 'image-resource-stop.json').exists()):
            raise ValueError('Not an untouched image continuation checkpoint')
        atomic_json(prediction / 'image-continuation.json', {
            'reuse_completed_image_scan': True, 'source_scan_retried': False, 'oracle_read': False,
            'adapter_sha256': hashlib.sha256((ROOT / 'benchmarks/predict_dropwizard_control.py').read_bytes()).hexdigest()})
        return image_prediction(work, prediction)
    if prediction.exists():
        raise FileExistsError('Preserve attempted prediction')
    prediction.mkdir()
    atomic_json(prediction / 'adapter-freeze.json', {
        'adapter_sha256': hashlib.sha256((ROOT / 'benchmarks/predict_dropwizard_control.py').read_bytes()).hexdigest(),
        'candidate_freeze_sha256': hashlib.sha256((output / 'candidate-freeze.json').read_bytes()).hexdigest(),
        'before_prediction': True, 'oracle_read': False})
    tool = ROOT / 'benchmarks/.work/trivy-r34/trivy.exe'
    prior = json.loads((ROOT / 'benchmarks/results/trivy-reactor-image-v3/run.json').read_bytes())
    if hashlib.sha256(tool.read_bytes()).hexdigest() != prior['binary_sha256']:
        raise ValueError('Trivy changed')
    cache = ROOT / 'benchmarks/.work/trivy-reactor-image-v1/cache'
    with (cache / 'java-db/trivy-java.db').open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != prior['database']['sha256']:
            raise ValueError('Frozen Java DB changed')
    projection = work / 'source-optional-projection-v1'
    if projection.exists():
        raise FileExistsError('Preserve previous projection')
    trace = []
    for name in command(['git', '-C', str(source), 'ls-files', '--', '*pom.xml']).splitlines():
        if name.startswith('/') or '..' in name.split('/') or '\\' in name:
            raise ValueError('Unsafe source path')
        raw = (source / name).read_bytes()
        projected, changes = project_pom(raw)
        path = projection / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(projected)
        trace.append({'path': name, 'source_sha256': hashlib.sha256(raw).hexdigest(),
                      'projection_sha256': hashlib.sha256(projected).hexdigest(), 'changes': changes})
    atomic_json(prediction / 'projection.json', {'files': trace, 'oracle_read': False})
    configuration = ROOT / 'benchmarks/results/trivy-reactor-source-optional-mirror-v1/trivy.yaml'
    shutil.copyfile(configuration, prediction / 'trivy.yaml')
    for mode in ('image', 'source'):
        directory = prediction / mode
        directory.mkdir()
        args = ([str(tool), 'image', '--input', str(work / 'image.tar'), '--offline-scan',
                 '--cache-dir', str(cache)] if mode == 'image' else
                [str(tool), 'fs', str(projection), '--config', str(prediction / 'trivy.yaml'),
                 '--cache-dir', str(directory / 'cache')])
        args += ['--format', 'cyclonedx', '--skip-db-update', '--skip-java-db-update',
                 '--skip-version-check', '--output', str(directory / 'sbom.json')]
        environment = {k: v for k, v in os.environ.items()
                       if k.upper() in ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC')}
        environment.update(TEMP=str(directory), TMP=str(directory), HOME=str(directory), USERPROFILE=str(directory))
        started = time.monotonic()
        try:
            process = subprocess.run(args, env=environment, capture_output=True, timeout=180, check=False)
            code, log = process.returncode, process.stdout + process.stderr
        except subprocess.TimeoutExpired as error:
            code, log = None, (error.stdout or b'') + (error.stderr or b'') + b'\nTIMEOUT180'
        (directory / 'scan.log').write_bytes(log)
        atomic_json(directory / 'run.json', {'exit_code': code, 'command': args,
                    'elapsed_seconds': time.monotonic() - started, 'oracle_read': False})
        if code != 0:
            raise RuntimeError('Frozen ' + mode + ' candidate failed; preserve logs, do not score partial output')
        if mode == 'source':
            atomic_json(directory / 'owner-predictions.json', {
                'owners': extract(json.loads((directory / 'sbom.json').read_bytes())), 'oracle_read': False,
                'profile_activation': 'UNKNOWN_FROM_PASSIVE_SOURCE'})
    return image_prediction(work, prediction)


def image_prediction(work, prediction):
    source = work / 'src'
    import bounded_jar_evidence as bounded
    readers, witnesses = [], {}
    original_collect = payload.collect

    def make_files(archive, document):
        files = bounded.JarFiles(archive, document)
        readers.append(files)
        return files

    def collect(document):
        with patch.object(payload, 'ImageFiles', make_files), patch.object(
                payload, '_java', lambda artifact, files: files.witness(artifact)):
            rows = original_collect(document, work / 'image.tar')
        witnesses.update(rows)
        return rows

    config = scanner.IMAGE_CONFIG
    for suffix in ('jar', 'war', 'ear', 'zip', 'hpi', 'jpi', 'nar', 'jmod'):
        config = config.replace('      - "**/*.' + suffix + '"\n', '')
    analysis = work / 'analysis-frozen-r98-input-v1'
    settings = Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'),
                        registry_hosts=('docker.io',), image_archive=str(work / 'image.tar'))
    with patch.object(scanner, 'IMAGE_CONFIG', config), patch.object(scanner, 'collect_payload', collect):
        analyze_local(source, 'docker.io/sbom-creator-benchmark/paired-dropwizard:v1', analysis, settings)
    image = json.loads((analysis / 'image.syft.json').read_bytes())
    source_catalog = json.loads((analysis / 'source.syft.json').read_bytes())
    peer = json.loads((prediction / 'image/sbom.json').read_bytes())
    if image['descriptor']['version'] != '1.51.1' or [(t['name'], t['version']) for t in
            peer['metadata']['tools']['components']] != [('trivy', '0.75.0')]:
        raise ValueError('Frozen producer version differs')
    atomic_json(prediction / 'witnesses.json', witnesses)
    adapted, evidence, audit = supplement(image, peer, witnesses, work / 'image.tar')
    atomic_json(prediction / 'supplement.json', audit)
    atomic_json(prediction / 'image-original.syft.json', image)
    provenance = copy.deepcopy(json.loads((analysis / 'provenance.json').read_bytes()))
    provenance['image']['payload_evidence'] = evidence
    provenance['image']['experimental_trivy_only'] = {
        'producer': CATALOGER, 'version': '0.75.0', 'runtime_changed': False,
        'audit_sha256': hashlib.sha256((prediction / 'supplement.json').read_bytes()).hexdigest(),
        'code_sha256': hashlib.sha256((ROOT / 'benchmarks/trivy_only_payload.py').read_bytes()).hexdigest(),
        'original_syft_inventory_preserved': True}
    final = work / 'analysis-frozen-r98-final-v1'
    with patch.dict(core._DIRECT_CATALOGERS, {CATALOGER: 'archive_metadata'}), patch.object(
            core, 'PAYLOAD_CATALOGERS', core.PAYLOAD_CATALOGERS | {CATALOGER}), patch.object(
            core, 'RULES_POLICY_VERSION', 'experimental-trivy-only-payload-v1'):
        summary = publish_catalogs(source_catalog, adapted, final, settings, rules_assessor, provenance)
    for view in ('final', 'os', 'full'):
        document = json.loads((final / (view + '.cdx.json')).read_bytes())
        validate_cyclonedx(document)
        shutil.copyfile(final / (view + '.cdx.json'), prediction / (view + '.cdx.json'))
    atomic_json(prediction / 'image-completed.json', {'oracle_read': False, 'summary': summary,
                'readers': [reader.stats for reader in readers], 'peak_rss_bytes': None,
                'runtime_changed': False, 'source_graph_not_integrated_into_final': True,
                'source_scan_failed': (prediction / 'failure.json').exists()})
    print('Frozen image prediction completed; source status remains separately recorded')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--continue-image', action='store_true')
    try:
        main(parser.parse_args().continue_image)
    except (RuntimeError, ValueError, OSError) as error:
        directory = ROOT / 'benchmarks/results/dropwizard-frozen-control-v1/prediction-v1'
        if directory.exists() and not (directory / 'failure.json').exists():
            atomic_json(directory / 'failure.json', {
                'status': 'FAILED_PREDICTION', 'error_type': type(error).__name__,
                'accuracy': None, 'oracle_read': False, 'runtime_changed': False,
                'note': 'Preserve engine logs and partial artifacts; not a successful empty prediction'})
        raise

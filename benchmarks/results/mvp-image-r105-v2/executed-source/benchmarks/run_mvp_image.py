"""Actual unpatched image-only runtime, with no source or build-label inputs."""
import argparse
import hashlib
import json
import time
from pathlib import Path

from run import ROOT, atomic_json

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze

OUTPUT = ROOT/'benchmarks/results/mvp-image-r105-v1'
CASES = {
    'boot': ('paired-spring-petclinic-v1', None),
    'javalin': ('paired-javalin-reactor-v1', None),
    'dropwizard': ('paired-dropwizard-reactor-v1', None),
    'microservices': ('paired-petclinic-microservices-r104',
        'sha256:0baa31188e29b4df33890b7664c46c6e8fd4c9a4ca53731db83ad05e6cb6ad95'),
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    global OUTPUT
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', default='mvp-image-r105-v2')
    args = parser.parse_args()
    if Path(args.run_id).name != args.run_id or not args.run_id.startswith('mvp-image-'):
        raise ValueError('Unsafe run namespace')
    OUTPUT = ROOT/'benchmarks/results'/args.run_id
    if OUTPUT.exists():
        raise FileExistsError('Preserve completed or attempted run')
    code = list((ROOT/'src/sbom_creator').rglob('*.py')) + list((ROOT/'src/sbom_creator/schemas').glob('*.json')) + [Path(__file__), ROOT/'Dockerfile']
    tools = {'syft': ROOT/'.tools/syft/syft.exe', 'trivy': ROOT/'benchmarks/.work/trivy-r34/trivy.exe',
             'crane': ROOT/'benchmarks/.work/crane-r94/crane.exe'}
    cache = ROOT/'benchmarks/.work/trivy-reactor-image-v1/cache'
    atomic_json(OUTPUT/'freeze.json', {'oracle_read': False, 'runtime_changed': True,
        'source_input': False, 'partition': 'disclosed-development-regression',
        'code_sha256': {str(p.relative_to(ROOT)): sha(p) for p in code},
        'tool_sha256': {name: sha(path) for name, path in tools.items()},
        'database_sha256': sha(cache/'java-db/trivy-java.db')})
    completed = []
    for name, (pair, digest) in CASES.items():
        work = ROOT/'benchmarks/.work'/pair
        archive = work/'image.tar'
        # Previously scanned immutable identity is an input binding, not oracle labels.
        if digest is None:
            image = json.loads((work/'analysis-seekable-payload-v4/image.syft.json').read_bytes())
            digest = image['source']['metadata']['manifestDigest']
        directory = OUTPUT/name
        settings = Settings(syft_binary=str(tools['syft']), trivy_binary=str(tools['trivy']),
            crane_binary=str(tools['crane']), trivy_cache_dir=str(cache),
            image_archive=str(archive), registry_hosts=('docker.io',), java_backend='disabled',
            image_temp_dir=str(ROOT/'benchmarks/.work/mvp-image-temporary'))
        atomic_json(directory/'invocation.json', {'image': 'docker.io/library/sbom-mvp@'+digest,
            'archive_sha256': sha(archive), 'repository_url': None, 'commit': None,
            'project_execution': False, 'oracle_read': False})
        started = time.monotonic()
        try:
            summary = analyze(None, None, 'docker.io/library/sbom-mvp@'+digest, directory/'analysis', settings)
            atomic_json(directory/'run.json', {'status': 'completed', 'oracle_read': False,
                'elapsed_seconds': time.monotonic()-started, 'summary': summary,
                'timing': 'full runtime source-empty + fresh Syft/Trivy + DB hashing + physical reads + publication; local archive acquisition excluded'})
            completed.append(name)
            print(name, 'completed', summary['final_count'], flush=True)
        except Exception as error:  # noqa: BLE001 -- preserve failed benchmark attempts without diagnostics leaking secrets
            atomic_json(directory/'run.json', {'status': 'FAILED', 'oracle_read': False,
                'elapsed_seconds': time.monotonic()-started, 'error_type': type(error).__name__,
                'error_stage': getattr(error, 'stage', None)})
            print(name, 'FAILED', type(error).__name__, flush=True)
    atomic_json(OUTPUT/'predictions-complete.json', {'oracle_read': False,
        'cases': list(CASES), 'completed': completed, 'failed': sorted(set(CASES)-set(completed))})


if __name__ == '__main__':
    main()

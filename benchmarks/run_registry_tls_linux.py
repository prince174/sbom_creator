"""External Docker launcher only; the isolated test process never gets Docker."""
from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import subprocess
import time

from run import ROOT, atomic_json

from sbom_creator.acquire import clean_environment, run_command


def main():
    work = ROOT / 'benchmarks/.work/registry-tls-linux-v1'
    output = ROOT / 'benchmarks/results/registry-tls-linux-v1'
    if work.exists() or output.exists():
        raise FileExistsError('Preserve existing experiment')
    work.mkdir()
    tools = ROOT / 'benchmarks/.work/crane-linux-r95'
    tool = json.loads((tools / 'provenance.json').read_bytes())
    assert hashlib.sha256((tools / 'crane').read_bytes()).hexdigest() == tool['binary_sha256']
    environment = clean_environment()

    def command(args, timeout=30):
        return run_command(args, cwd=work, env=environment, timeout=timeout,
                           max_output_bytes=1024 * 1024, label='External TLS harness',
                           monitored_paths=((work, 256 * 1024 * 1024),))

    base = command(['docker', 'image', 'inspect', 'python:3.12-slim', '--format', '{{.Id}}'])
    ca = work / 'ca'
    ca.mkdir()
    command(['C:/Program Files/Git/usr/bin/openssl.exe', 'req', '-x509', '-newkey', 'rsa:2048',
             '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
             '-keyout', str(ca / 'fixture.key'), '-out', str(ca / 'fixture.crt')])
    data = work / 'data'
    data.mkdir()
    args = ['docker', 'run', '--rm', '--name', 'sbom-tls-fixture-' + secrets.token_hex(6),
            '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--user=65532:65532', '--cpus=1', '--memory=512m', '--pids-limit=64',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m']
    name = args[4]
    mounts = [(tools / 'crane', '/tools/crane', True),
              (ROOT / 'benchmarks/check_registry_tls_linux.py', '/tools/check_registry_tls_linux.py', True),
              (ROOT / 'benchmarks/registry_fixture.py', '/tools/registry_fixture.py', True),
              (ROOT / 'benchmarks/.work/paired-javalin-reactor-v1/image.tar', '/input/image.tar', True),
              (ca, '/inputca', True), (data, '/work', False)]
    for source, target, readonly in mounts:
        args.extend(['--mount', f'type=bind,source={source},target={target}' + (',readonly' if readonly else '')])
    args.extend([base, 'python', '-B', '/tools/check_registry_tls_linux.py'])
    started = time.monotonic()
    try:
        command(args, timeout=150)
    finally:
        # Only our unique fixture name is eligible for cleanup.
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30, check=False,
                       env=environment)
        if (data / 'report.json').exists():
            output.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(data / 'report.json', output / 'harness.json')
    report = json.loads((data / 'report.json').read_bytes())
    assert report['status'] == 'PASSED'
    atomic_json(output / 'run.json', {'status': 'PASSED', 'tool': tool, 'linux_image_id': base,
                'elapsed_seconds': time.monotonic() - started,
                'external_docker_launcher_only': True, 'runtime_changed': False,
                'container_network': 'none', 'socket_mounted': False, 'source_or_reference_mounted': False,
                'read_only_root': True, 'user': '65532:65532', 'memory_limit_bytes': 512 * 1024 * 1024,
                'artifact_size_limit_sampled_bytes': 256 * 1024 * 1024,
                'code_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in (ROOT / 'benchmarks/check_registry_tls_linux.py',
                                             ROOT / 'benchmarks/registry_fixture.py')}})
    print(json.dumps({'status': report['status'], 'checks': report['checks']}))


if __name__ == '__main__':
    main()

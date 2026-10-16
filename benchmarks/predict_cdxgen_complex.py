"""External native-Maven cdxgen comparison on a new complex source, no oracle."""
import json
import subprocess
import time

from run import ROOT, atomic_json

IMAGE = 'sha256:11e944f4291e284eca333b829e840ce8fac56613744880aff87a9a730fe0d36a'


def main():
    source = ROOT/'benchmarks/.work/paired-petclinic-microservices-r104/src'
    output = ROOT/'benchmarks/results/java-runtime-direct-r104-control-v1/cdxgen'
    if output.exists():
        raise FileExistsError('Preserve competitor attempt')
    output.mkdir()
    name = 'sbom-cdxgen-r104-microservices'
    script = ('mkdir -p /tmp/home/.m2 /tmp/project && cp -R /src/. /tmp/project/ && '
        "printf '%s' '<settings><localRepository>/tmp/home/.m2/repository</localRepository><mirrors><mirror>"
        '<id>benchmark</id><mirrorOf>*</mirrorOf><url>https://maven-central.storage-download.googleapis.com/maven2/</url>'
        "</mirror></mirrors></settings>' > /tmp/home/.m2/settings.xml && cd /tmp/project && "
        'cdxgen -t java --recurse --spec-version 1.6 --fail-on-error -o /out/sbom.json .')
    command = ['docker', 'run', '--rm', '--name', name, '--read-only', '--user=65532:65532',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=3g', '--cpus=2', '--pids-limit=256',
        '--tmpfs', '/tmp:rw,size=2147483648',
        '--mount', 'type=bind,source='+str(source)+',target=/src,readonly',
        '--mount', 'type=bind,source='+str(output)+',target=/out',
        '-e', 'HOME=/tmp/home', '-e', 'PREFER_MAVEN_DEPS_TREE=true',
        '-e', 'MVN_ARGS=-s /tmp/home/.m2/settings.xml -Dscope=runtime -DskipTests -Dmaven.test.skip=true',
        '-e', 'MAVEN_OPTS=-XX:ActiveProcessorCount=2 -Xmx1536m -Duser.home=/tmp/home',
        '--entrypoint', 'sh', IMAGE, '-c', script]
    started = time.monotonic()
    try:
        run = subprocess.run(command, capture_output=True, timeout=900, check=False)
        code, log = run.returncode, run.stdout+run.stderr
    except subprocess.TimeoutExpired as error:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30, check=False)
        code, log = None, (error.stdout or b'')+(error.stderr or b'')+b'\nTIMEOUT900\n'
    (output/'run.log').write_bytes(log)
    atomic_json(output/'run.json', {'command': command, 'returncode': code,
        'seconds': time.monotonic()-started, 'oracle_read': False,
        'source_commit': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip(),
        'mode': 'external project tooling allowed; NOT passive production contract',
        'sbom_created': (output/'sbom.json').is_file()})
    print(json.dumps({'cdxgen_exit': code, 'sbom_created': (output/'sbom.json').is_file()}))


if __name__ == '__main__':
    main()

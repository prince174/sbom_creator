"""External whiteout/oversize fixtures for the experimental Syft content bridge."""
import json
import shutil
import tarfile

from run import ROOT, atomic_json, run_command
from syft_go_payload_bridge import read_payload

from sbom_creator.acquire import Settings
from sbom_creator.scanner import scan_image


def main():
    work = ROOT / 'benchmarks/.work/go-payload-failures-r46'
    work.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'benchmarks/.work/go-binary-info-r41/paired-hey-v1.binary', work / 'old.binary')
    (work / 'delete.go').write_text('package main\nimport "os"\nfunc main(){if err:=os.Remove("/application/app");err!=nil{panic(err)}}\n', encoding='utf-8')
    with (work / 'oversize.bin').open('wb') as stream:
        stream.truncate(32 * 1024 * 1024 + 1)
    recipe = ('FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS helper\n'
              'COPY delete.go /helper/delete.go\nRUN CGO_ENABLED=0 go build -o /helper/delete /helper/delete.go\n'
              'FROM scratch AS deleted\nCOPY old.binary /application/app\nCOPY --from=helper /helper/delete /delete\n'
              'RUN ["/delete"]\nUSER 65532\nCMD ["/not-executed"]\n'
              'FROM scratch AS oversize\nCOPY oversize.bin /application/app\nUSER 65532\nCMD ["/not-executed"]\n')
    (work / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!delete.go\n!old.binary\n!oversize.bin\n', encoding='utf-8')
    rows = []
    for name in ('deleted', 'oversize'):
        run_command(['docker', 'build', '--platform', 'linux/amd64', '--target', name, '--iidfile', str(work / (name + '.id')), str(work)], work / (name + '-build.log'))
        archive = work / (name + '.tar')
        run_command(['docker', 'image', 'save', '-o', str(archive), (work / (name + '.id')).read_text().strip()], work / (name + '-save.log'))
        settings = Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(archive))
        original, identity = scan_image('docker.io/sbom-creator-benchmark/failure:v1', work / (name + '.syft.json'), settings)
        paths = {f['location']['path']: f for f in original.get('files', [])}
        whiteouts = []
        if name == 'deleted':
            with tarfile.open(archive) as outer:
                manifest = json.load(outer.extractfile('manifest.json'))[0]
                for layer in manifest['Layers']:
                    with tarfile.open(fileobj=outer.extractfile(layer), mode='r|*') as entries:
                        whiteouts.extend(m.name for m in entries if m.name.endswith('/.wh.app'))
            if not whiteouts:
                raise ValueError('Deletion fixture has no whiteout')
        if name == 'deleted' and '/application/app' in paths:
            raise ValueError('Deleted binary remains in final filesystem')
        if name == 'oversize' and paths.get('/application/app', {}).get('metadata', {}).get('size') != 32 * 1024 * 1024 + 1:
            raise ValueError('Oversize fixture not recognized')
        targets = ['/application/app'] + (['/application/missing'] if name == 'deleted' else [])
        for target in targets:
            try:
                read_payload(archive, target, identity['image_config_digest'])
            except ValueError as error:
                if str(error) != 'Binary unavailable within content budget':
                    raise
            else:
                raise ValueError('Unavailable binary returned successful payload')
            rows.append({'case': name if target.endswith('/app') else 'missing', 'target': target,
                         'outcome': 'unavailable/UNKNOWN', 'stale_payload_returned': False,
                         'image_config_digest': identity['image_config_digest'],
                         'whiteout_members': whiteouts})
    report = {'experiment': 'R46', 'rows': rows, 'runtime_changed': False, 'direct_accuracy': None,
              'limitation': 'Archive backend and passive fixture reads; registry/auth and aggregate budget still untested'}
    atomic_json(ROOT / 'docs/syft-go-payload-failures-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

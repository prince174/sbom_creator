"""Build frozen passive helpers for a compiler-free Linux scratch fixture."""
import hashlib
import json
import shutil

from http_integration import command
from run import ROOT, atomic_json

BASE = 'golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac'


def main():
    work = ROOT / 'benchmarks/.work/go-helper-delivery-r51'
    work.mkdir(parents=True, exist_ok=True)
    frozen = json.loads((ROOT / 'benchmarks/go-g2-freeze-v1.json').read_bytes())['sha256']
    for name, digest in frozen.items():
        if hashlib.sha256((ROOT / 'benchmarks' / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen helper/rule changed')
    for name in ('go_source_index.go', 'go_binary_info.go'):
        shutil.copyfile(ROOT / 'benchmarks' / name, work / name)
    recipe = (f'FROM {BASE} AS build\nENV CGO_ENABLED=0 GOMAXPROCS=2 GOPROXY=off GOTOOLCHAIN=local\n'
              'COPY *.go /a/\nRUN mkdir /b && cp /a/*.go /b/\n'
              'RUN cd /a && go build -trimpath -buildvcs=false -o /out/index go_source_index.go && '
              'go build -trimpath -buildvcs=false -o /out/info go_binary_info.go\n'
              'RUN cd /b && go build -trimpath -buildvcs=false -o /out/index2 go_source_index.go && '
              'go build -trimpath -buildvcs=false -o /out/info2 go_binary_info.go && '
              'cmp /out/index /out/index2 && cmp /out/info /out/info2\n'
              'FROM scratch\nCOPY --from=build /out/ /helpers/\nUSER 65532:65532\n')
    (work / 'Dockerfile').write_text(recipe, encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!*.go\n', encoding='utf-8')
    command(['docker', 'build', '--network=none', '--platform=linux/amd64', '--iidfile',
             str(work / 'image.id'), str(work)], timeout=300)
    image = (work / 'image.id').read_text().strip()
    options = ['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
               '--security-opt=no-new-privileges', '--memory=256m', '--cpus=1', '--pids-limit=32']
    source = ROOT / 'benchmarks/.work/paired-hey-v1/src'
    payload = ROOT / 'benchmarks/.work/go-binary-info-r41/paired-hey-v1.binary'
    index = json.loads(command(options + ['--mount', f'type=bind,source={source},target=/input,readonly',
                                          image, '/helpers/index', '/input', 'linux', 'amd64']))
    info = json.loads(command(options + ['--mount', f'type=bind,source={payload},target=/payload,readonly',
                                         image, '/helpers/info', '/payload']))
    native_index = json.loads(command([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'),
                                       str(source), 'linux', 'amd64']))
    native_info = json.loads(command([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(payload)]))
    if index != native_index or info != native_info:
        raise ValueError('Linux delivery differs from frozen Windows helper output')
    atomic_json(ROOT / 'docs/go-helper-delivery-v1.json', {
        'experiment': 'R51', 'builder': BASE, 'fixture_image_id': image,
        'helper_sources': {name: frozen[name] for name in ('go_source_index.go', 'go_binary_info.go')},
        'different_build_paths_identical': True, 'linux_windows_outputs_equal': True,
        'read_only_nonroot_no_network_no_capabilities': True, 'compiler_in_final_image': False,
        'parser_version': index['parser_version'], 'runtime_changed': False, 'direct_accuracy': None})
    print('R51 passed: deterministic Linux helpers and matching passive outputs')


if __name__ == '__main__':
    main()

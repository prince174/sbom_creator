"""Source-only main index; report ambiguity without using reference main path."""
import json
import subprocess

from paired_express import sha
from run import ROOT, atomic_json


def main():
    helper = ROOT / 'benchmarks/.work/go-source-index-r40/index.exe'
    rows = []
    for name in ('paired-hey-v1', 'go-multimain-r39'):
        work = ROOT / 'benchmarks/.work' / name
        image = json.loads((work / 'analysis/image.syft.json').read_bytes())
        owners = [a for a in image['artifacts'] if a.get('metadata', {}).get('goBuildSettings')]
        if len(owners) != 1:
            raise ValueError('Ambiguous binary owner')
        metadata = owners[0]['metadata']
        settings = {s['key']: s['value'] for s in metadata['goBuildSettings']}
        if settings.get('CGO_ENABLED') != '0' or settings.get('-tags'):
            raise ValueError('Unsupported build flags')
        result = json.loads(subprocess.check_output([str(helper), str(work / 'src'), settings['GOOS'], settings['GOARCH']], timeout=30))
        if result['parser_version'] != metadata['goCompiledVersion']:
            raise ValueError('Parser release tags differ from binary toolchain')
        mains = result['main_directories']
        rows.append({'project': name, 'index': result, 'syft_build_metadata_fields': sorted(metadata),
                     'main_selection': 'UNIQUE_SOURCE_CANDIDATE' if len(mains) == 1 else 'UNKNOWN/ambiguous_main',
                     'chosen_directory_candidate': mains[0] if len(mains) == 1 else None,
                     'direct_edges_proven': False})
    fixtures = ROOT / 'benchmarks/.work/go-source-index-r40/fixtures'
    fixtures.mkdir(exist_ok=True)
    (fixtures / 'main.go').write_text('package main\n/* package main; import "fake" */\nfunc main(){}\n', encoding='utf-8')
    for folder, suffix in [('inactive', '_windows.go'), ('tests', '_test.go'), ('cgo', '.go')]:
        target = fixtures / folder
        target.mkdir(exist_ok=True)
        content = 'package main\n' + ('import "C"\n' if folder == 'cgo' else '') + 'func main(){}\n'
        (target / ('main' + suffix)).write_text(content, encoding='utf-8')
    negative = json.loads(subprocess.check_output([str(helper), str(fixtures), 'linux', 'amd64'], timeout=30))
    if negative['main_directories'] != ['.']:
        raise ValueError('Inactive/test/cgo selection failed')
    report = {'experiment': 'R40', 'rows': rows, 'selection_fixture': negative,
              'helper_binary_sha256': sha(helper), 'helper_source_sha256': sha(ROOT / 'benchmarks/go_source_index.go'),
              'runtime_changed': False, 'direct_precision': None, 'direct_recall': None,
              'limitation': 'Main selection stage only, no source import graph or binary entry-path extraction'}
    atomic_json(ROOT / 'docs/go-main-selection-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

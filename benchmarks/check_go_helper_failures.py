"""Negative inputs for frozen passive readers; never execute target code."""
import json
import tempfile
import time
from pathlib import Path

from run import ROOT, atomic_json

from sbom_creator.acquire import clean_environment, run_command


def main():
    binary_helper = ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'
    source_helper = ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'
    rows = []
    with tempfile.TemporaryDirectory(prefix='sbom-go-r54-') as directory:
        work = Path(directory)
        invalid = work / 'invalid.binary'
        invalid.write_bytes(b'MZ\x00not-a-go-executable')
        oversize = work / 'oversize.binary'
        with oversize.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        malformed = work / 'malformed'
        malformed.mkdir()
        (malformed / 'main.go').write_text('package main\nimport (', encoding='utf-8')
        large = work / 'large'
        large.mkdir()
        (large / 'main.go').write_bytes(b'package main\n//' + b'x' * (1024 * 1024))
        for name, helper, args in [
            ('invalid_binary', binary_helper, [str(invalid)]),
            ('oversized_binary', binary_helper, [str(oversize)]),
            ('malformed_source', source_helper, [str(malformed), 'linux', 'amd64']),
            ('oversized_source_file', source_helper, [str(large), 'linux', 'amd64'])]:
            started = time.monotonic()
            try:
                run_command([str(helper), *args], cwd=work, env=clean_environment(), timeout=5,
                            max_output_bytes=4096, label='Passive reader negative fixture')
            except RuntimeError:
                rows.append({'case': name, 'status': 'REJECTED',
                             'elapsed_seconds': round(time.monotonic() - started, 3)})
            else:
                raise AssertionError('Negative fixture accepted: ' + name)
        passive = work / 'passive'
        passive.mkdir()
        # A valid source that would panic if run; imports-only parsing must succeed.
        (passive / 'main.go').write_text('package main\nimport "fmt"\nfunc init(){panic("target executed")}\nfunc main(){fmt.Println("unused")}\n', encoding='utf-8')
        raw = run_command([str(source_helper), str(passive), 'linux', 'amd64'], cwd=work,
                          env=clean_environment(), timeout=5, max_output_bytes=4096,
                          label='Passive source positive fixture')
        parsed = json.loads(raw)
        if parsed['packages']['.']['imports'] != ['fmt'] or parsed['main_directories'] != ['.']:
            raise AssertionError('Passive parsing differs')
    atomic_json(ROOT / 'docs/go-helper-failures-v1.json', {'experiment': 'R54', 'rows': rows,
                'panic_init_source_parsed': True, 'runtime_changed': False, 'direct_accuracy': None,
                'limitation': 'Small deterministic negative set; not fuzzing or general parser safety proof'})
    print('R54 passed: four negative inputs rejected; panic-init source parsed passively')


if __name__ == '__main__':
    main()

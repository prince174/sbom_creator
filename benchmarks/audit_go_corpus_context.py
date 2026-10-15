"""Source prerequisite audit of ten original Go projects, not accuracy scoring."""
import hashlib
import json
import time
from collections import Counter

from go_g1_candidates import declarations
from http_integration import command
from run import ROOT, atomic_json

from sbom_creator.acquire import clean_environment, run_command


def main():
    manifest = json.loads((ROOT / 'benchmarks/manifest.json').read_bytes())
    split = json.loads((ROOT / 'benchmarks/direct-evaluation-split-v1.json').read_bytes())
    frozen = json.loads((ROOT / 'benchmarks/go-g2-freeze-v1.json').read_bytes())['sha256']
    for name, digest in frozen.items():
        if hashlib.sha256((ROOT / 'benchmarks' / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Frozen source changed')
    rows = []
    for project in manifest['repositories']:
        if project['language'] != 'Go':
            continue
        started = time.monotonic()
        source = ROOT / 'benchmarks/.work' / project['id'] / 'src'
        row = {'project': project['id'], 'commit': project['commit'],
               'partition': 'development' if project['id'] in split['development'] else 'fixed-control',
               'binary_context_status': 'UNKNOWN', 'binary_context_reason': 'not_acquired_in_source_audit'}
        if command(['git', '-C', str(source), 'rev-parse', 'HEAD']) != project['commit']:
            raise ValueError('Source commit differs')
        if command(['git', '-C', str(source), 'status', '--porcelain']):
            raise ValueError('Source dirty')
        try:
            path = source / 'go.mod'
            if path.stat().st_size > 1024 * 1024:
                raise ValueError('manifest_budget')
            module, _ = declarations(path.read_bytes())
            row.update(declaration_status='SUPPORTED', module=module)
        except ValueError as error:
            row.update(declaration_status='UNKNOWN', declaration_reason=str(error))
        except OSError:
            row.update(declaration_status='UNKNOWN', declaration_reason='manifest_missing_or_unreadable')
        try:
            raw = run_command([str(ROOT / 'benchmarks/.work/go-source-index-r42/index.exe'),
                               str(source), 'linux', 'amd64'], cwd=source, env=clean_environment(),
                              timeout=30, max_output_bytes=4 * 1024 * 1024, label='Go source audit')
            index = json.loads(raw)
            row.update(source_parse_status='PARSED', files_checked=index['files_checked'],
                       main_directories=index['main_directories'])
        except (RuntimeError, ValueError):
            row.update(source_parse_status='UNKNOWN', source_parse_reason='bounded_parser_failed')
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        rows.append(row)
    if len(rows) != 10:
        raise ValueError('Expected ten original Go projects')
    report = {'experiment': 'R55', 'rows': rows,
              'declarations': dict(Counter(r['declaration_status'] for r in rows)),
              'source_parsing': dict(Counter(r['source_parse_status'] for r in rows)),
              'direct_accuracy': None, 'runtime_changed': False,
              'limitation': 'Source prerequisites only. No binary eligibility, direct edges, or ground truth inferred.'}
    atomic_json(ROOT / 'docs/go-corpus-context-v1.json', report)
    print(json.dumps({k: v for k, v in report.items() if k != 'rows'}))


if __name__ == '__main__':
    main()

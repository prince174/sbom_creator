"""Read-only history audit: no scanner/publisher/oracle retry of R106 Chalk.

The original safe failure record omitted the failing operation and OS error
codes. A later successful replay cannot recover an absent original traceback.
"""
from __future__ import annotations

import ast
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'benchmarks/results/mvp-r113-chalk-history-v1'
ORIGINAL = ROOT / 'benchmarks/results/mvp-r106-v1/javascript/paired-chalk-v1'
FROZEN = ROOT / 'benchmarks/results/mvp-r106-v1/javascript'
REPLAY = ROOT / 'benchmarks/results/chalk-publish-diagnostic-v1'


def read(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def function_hashes(path):
    raw = path.read_text(encoding='utf-8')
    return {node.name: hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            for node in ast.parse(raw).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def main():
    if OUTPUT.exists():
        raise FileExistsError('Preserve the completed no-retry history audit')
    freeze = read(FROZEN / 'freeze.json')
    run = read(ORIGINAL / 'run.json')
    failure = read(ORIGINAL / 'analysis.diagnostics/failure.json')
    invocation = read(ORIGINAL / 'invocation.json')
    replay = read(REPLAY / 'run.json')
    replay_freeze = read(REPLAY / 'freeze.json')
    if (run.get('status') != 'FAILED' or run.get('error_type') != 'AnalysisError'
            or run.get('error_stage') != 'reconcile_convert_validate'
            or failure != {'status': 'failed', 'stage': 'reconcile_convert_validate',
                           'error_type': 'PermissionError', 'final_published': False}
            or invocation.get('oracle_read') is not False
            or invocation.get('repository_url') is not None or invocation.get('commit') is not None):
        raise ValueError('Original safe failure evidence differs')
    diagnostics = ORIGINAL / 'analysis.diagnostics'
    expected_diagnostics = {'failure.json', 'source.syft.json', 'image.syft.json', 'provenance.json'}
    if {path.name for path in diagnostics.iterdir()} != expected_diagnostics:
        raise ValueError('Unexpected original diagnostic artifacts; review before claiming missing traceback')
    if (replay.get('status') != 'completed' or replay.get('new_scans') is not False
            or replay.get('oracle_read') is not False or replay.get('original_attempt_preserved') is not True):
        raise ValueError('Separate successful diagnostic scope differs')
    files = [ORIGINAL / 'run.json', ORIGINAL / 'invocation.json', FROZEN / 'freeze.json',
             FROZEN / 'executed-runner.py', REPLAY / 'run.json', REPLAY / 'freeze.json',
             REPLAY / 'executed-runner.py', *(diagnostics / name for name in sorted(expected_diagnostics))]
    source_pairs = {}
    for name in ('pipeline.py', 'scanner.py', 'acquire.py'):
        previous = FROZEN / 'executed-source/sbom_creator' / name
        current = ROOT / 'src/sbom_creator' / name
        if sha(previous) != freeze['code_sha256']['sbom_creator/' + name]:
            raise ValueError('Original executing source snapshot changed')
        files.extend((previous, current))
        original_functions, current_functions = function_hashes(previous), function_hashes(current)
        source_pairs[name] = {'old_sha256': sha(previous), 'current_sha256': sha(current),
            'bytes_equal': sha(previous) == sha(current), 'functions_ast_equal': {
                name: current_functions.get(name) == digest for name, digest in original_functions.items()}}
    for relative, expected in replay_freeze['input_sha256'].items():
        path = ROOT / relative
        if path.parent != diagnostics or sha(path) != expected:
            raise ValueError('Successful diagnostic did not consume exactly the retained catalogs/provenance')
    OUTPUT.mkdir(parents=True)
    shutil.copyfile(__file__, OUTPUT / 'executed-audit.py')
    snapshots = OUTPUT / 'source-snapshots'
    snapshots.mkdir()
    for name in source_pairs:
        shutil.copyfile(FROZEN / 'executed-source/sbom_creator' / name, snapshots / ('r106-' + name))
        shutil.copyfile(ROOT / 'src/sbom_creator' / name, snapshots / ('current-' + name))
    report = {'reference_accessed': False, 'classifier_or_publisher_invoked': False,
        'new_scans_builds_or_project_execution': False, 'original_attempt_unchanged': True,
        'proven': {'original_status': run['status'], 'public_error_type': run['error_type'],
            'underlying_error_type': failure['error_type'], 'recorded_stage': failure['stage'],
            'elapsed_seconds': run['elapsed_seconds'], 'final_published_recorded': False,
            'original_final_directory_present_now': (ORIGINAL / 'analysis').exists(),
            'completed_scans_retained': ['source.syft.json', 'image.syft.json'],
            'no_original_traceback_errno_winerror_operation_or_filename_saved': True,
            'separate_cached_publisher_diagnostic_status': replay['status'],
            'separate_diagnostic_elapsed_seconds': replay['elapsed_seconds'],
            'successful_replay_has_no_exception_frames': 'exception_frames' not in replay,
            'pipeline_bytes_unchanged_since_failed_run': source_pairs['pipeline.py']['bytes_equal']},
        'source_comparison': source_pairs,
        'not_proven': ['the exact failing filesystem or converter operation',
            'a Windows sharing violation, antivirus interference or a concurrent reader',
            'a defect specific to Chalk package bytes', 'a locking fix from a later successful run'],
        'remaining_static_failure_sites': [
            'staging creation and write_json temporary file write',
            'write_json atomic replacement after at most20 attempts/19x25ms delays',
            'selected JSON read, converter temporary process/config/output files and cleanup',
            'final staging directory rename, currently without operation-specific diagnostic',
            'TemporaryDirectory cleanup; final_published is currently hardcoded false even after commit'],
        'next_bounded_checks': [
            'Add fixed internal publication checkpoints and safe fixed OS error facts; never export exception messages, paths or locals',
            'Fault-inject exactly one write/replace/convert/rename/cleanup failure per isolated synthetic case; preserve scans and prevent partial final',
            'Prove transient replacement retry is bounded and permanent denial is not silently retried forever',
            'Prove post-commit cleanup does not falsely report unpublished output',
            'Only a new explicit diagnostic hypothesis justifies another actual Chalk run; do not retry merely to obtain success']}
    write(OUTPUT / 'report.json', report)
    write(OUTPUT / 'input-manifest.json', {'oracle_accessed': False,
        'audit_sha256': sha(__file__),
        'input_sha256': {path.relative_to(ROOT).as_posix(): sha(path) for path in files},
        'output_sha256': {path.relative_to(OUTPUT).as_posix(): sha(path) for path in sorted(OUTPUT.rglob('*'))
                          if path.is_file()}})
    print(json.dumps(report['proven']))


if __name__ == '__main__':
    main()

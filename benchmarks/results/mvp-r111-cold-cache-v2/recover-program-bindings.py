"""Recover literal program bytes from the frozen helper, never execute its AST.

This is not independent capture of Docker's executed argv. The reduced container
inspection receipts do not retain Config.Cmd/Args; removed containers are not
recreated to fill that evidence gap.
"""
import ast
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
frozen = json.loads((root / 'candidate-freeze.json').read_bytes())
source = (root / 'executed-harness.py').read_bytes()
assert hashlib.sha256(source).hexdigest() == frozen['harness_sha256']
parsed = ast.parse(source)
values = {}
for node in parsed.body:
    if isinstance(node, ast.Assign):
        names = [item.id for item in node.targets if isinstance(item, ast.Name)]
        for name in names:
            if name in ('PROGRAM', 'PREFLIGHT'):
                assert name not in values
                value = ast.literal_eval(node.value)
                assert isinstance(value, str)
                values[name] = value.encode('utf-8')
assert set(values) == {'PROGRAM', 'PREFLIGHT'}
folder = root / 'reconstructed-frozen-programs'
folder.mkdir()
records = {}
for variable, name, key in (
        ('PROGRAM', 'pipeline.py', 'container_program_sha256'),
        ('PREFLIGHT', 'native-preflight.py', 'preflight_program_sha256')):
    raw = values[variable]
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == frozen[key]
    destination = folder / name
    with destination.open('xb') as stream:
        stream.write(raw)
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == digest
    records[variable] = {'file': destination.relative_to(root).as_posix(),
                         'bytes': len(raw), 'sha256': digest,
                         'equals_pre_execution_freeze': True}
report = {
    'status': 'passed', 'method': 'reconstructed-from-frozen-executed-harness-AST-literals',
    'independent_executed_container_argv_capture': False,
    'limitation': 'Saved reduced container inspections omit Config.Cmd/Args; containers were removed. No argv was invented or re-executed.',
    'frozen_executed_harness_sha256': hashlib.sha256(source).hexdigest(),
    'recovery_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'programs': records, 'original_CRLF_snapshots_changed': False,
    'docker_or_network_operations_performed': False,
    'source_or_reference_read': False}
with (root / 'reconstructed-program-binding.json').open('x', encoding='utf-8', newline='\n') as stream:
    stream.write(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))

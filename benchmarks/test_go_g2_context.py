import copy
import json

import pytest
from go_g2_context import context
from http_integration import command
from run import ROOT


@pytest.fixture(scope='module')
def actual():
    payload = ROOT / 'benchmarks/.work/go-binary-info-r41/paired-hey-v1.binary'
    info = json.loads(command([str(ROOT / 'benchmarks/.work/go-binary-info-r41/info.exe'), str(payload)]))
    settings = {s['Key']: s['Value'] for s in info['Settings']}
    return info, info['Main']['Path'], settings['vcs.revision']


def test_real_binary_context(actual):
    result = context(*actual)
    assert result['status'] == 'ELIGIBLE_CANDIDATE'
    assert result['entry'] == '.'
    assert result['direct_edge_proven'] is False


@pytest.mark.parametrize('mutation', ['duplicate', 'dirty', 'revision', 'tags', 'cgo', 'platform',
                                     'toolchain', 'owner', 'prefix', 'traversal', 'replace', 'depduplicate', 'workspace'])
def test_unsupported_context_is_unknown(actual, mutation):
    info, module, commit = copy.deepcopy(actual)
    extra = {}
    if mutation == 'duplicate':
        info['Settings'].append(info['Settings'][0])
    elif mutation in ('dirty', 'revision', 'cgo', 'platform'):
        key, value = {'dirty': ('vcs.modified', 'true'), 'revision': ('vcs.revision', '0' * 40),
                      'cgo': ('CGO_ENABLED', '1'), 'platform': ('GOARCH', 'arm64')}[mutation]
        next(s for s in info['Settings'] if s['Key'] == key)['Value'] = value
    elif mutation == 'tags':
        info['Settings'].append({'Key': '-tags', 'Value': 'custom'})
    elif mutation == 'toolchain':
        info['GoVersion'] = 'go1.25.0'
    elif mutation == 'owner':
        info['Main']['Path'] = 'other/module'
    elif mutation == 'prefix':
        info['Path'] = module + '-other/cmd'
    elif mutation == 'traversal':
        info['Path'] = module + '/../cmd'
    elif mutation == 'replace':
        info['Deps'][0]['Replace'] = {'Path': '../local'}
    elif mutation == 'depduplicate':
        info['Deps'].append(info['Deps'][0])
    else:
        extra['workspace'] = True
    assert context(info, module, commit, **extra)['status'] == 'UNKNOWN'

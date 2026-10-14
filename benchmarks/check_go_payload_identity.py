"""Archive rescan identity rejection, without invoking application executables."""
import json

from run import ROOT, atomic_json
from syft_go_payload_bridge import read_payload


def main():
    rows = []
    for project, path in [('paired-hey-v1', '/application/hey'),
                          ('paired-lazygit-v1', '/application/lazygit')]:
        try:
            read_payload(ROOT / 'benchmarks/.work' / project / 'image.tar', path,
                         'sha256:' + '0' * 64)
        except ValueError as error:
            if str(error) != 'Rescanned image differs':
                raise
            rows.append({'project': project, 'rejected': True, 'payload_returned': False,
                         'reason': str(error)})
        else:
            raise AssertionError('Mismatched image identity accepted')
    result = {'experiment': 'R48', 'rows': rows, 'runtime_changed': False,
              'registry_tested': False, 'direct_accuracy': None}
    atomic_json(ROOT / 'docs/go-payload-identity-v1.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    main()

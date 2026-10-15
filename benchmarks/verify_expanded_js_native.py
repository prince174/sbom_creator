"""Read-only native npm graph validation for new single-root JS controls."""
import argparse
import json
import re
import subprocess
import uuid

from compare_java_js import all_components
from paired_express import npm_component_name, root_dependencies
from run import ROOT, atomic_json


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--pair',required=True);args=parser.parse_args()
    if not re.fullmatch(r'paired-[a-z0-9-]+-v[0-9]+',args.pair):raise ValueError('Invalid pair')
    work=ROOT/'benchmarks/.work'/args.pair;reference_dir=ROOT/'benchmarks/references'/args.pair
    package=json.loads((work/'src/package.json').read_bytes())
    if package.get('workspaces') or (work/'src/pnpm-workspace.yaml').exists():
        raise ValueError('Workspace graphs require separate owner validation')
    image=(work/'runtime.id').read_text().strip();name='sbom-npm-native-'+uuid.uuid4().hex[:10]
    command=['docker','run','--rm','--name',name,'--network=none','--cap-drop=ALL','--security-opt=no-new-privileges',
             '--memory=512m','--cpus=2','--pids-limit=256','--entrypoint','npm',image,'ls','--all','--omit=dev','--json']
    try:
        run=subprocess.run(command,capture_output=True,timeout=60,check=False)
    finally:
        subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30,check=False)
    if len(run.stdout)>16*1024*1024:raise ValueError('Native graph output budget exceeded')
    native=json.loads(run.stdout)
    reference=json.loads((reference_dir/'sbom.json').read_bytes())
    by_ref={c['bom-ref']:c for c in all_components(reference)}
    expected={npm_component_name(by_ref[r]):by_ref[r]['version'] for r in root_dependencies(reference)}
    actual={name:node.get('version') for name,node in native.get('dependencies',{}).items()}
    valid=(run.returncode==0 and (native.get('name'),native.get('version'))==(package['name'],package['version'])
           and expected==actual and set(expected)==set(package.get('dependencies',{})))
    out=ROOT/'benchmarks/results/expanded-v1'/args.pair
    atomic_json(out/'native-npm-tree.json',native)
    atomic_json(out/'native-root-validation.json',{'image':image,'command':command,'returncode':run.returncode,
                'expected':expected,'actual':actual,'status':'VERIFIED' if valid else 'FAILED',
                'scope':'Root production dependencies; workspaces rejected; no project execution or network'})
    print(args.pair,'native root',valid,len(expected))
    if not valid:raise ValueError('Native/reference/declaration root mismatch')


if __name__=='__main__':
    main()

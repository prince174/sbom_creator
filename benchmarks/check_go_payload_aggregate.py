import json
import shutil

from go_payload_plan import plan
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.scanner import scan_image


def main():
    work = ROOT / 'benchmarks/.work/go-payload-aggregate-r47'
    work.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'benchmarks/.work/go-binary-info-r41/paired-hey-v1.binary', work / 'hey')
    shutil.copyfile(ROOT / 'benchmarks/.work/paired-lazygit-v1/payload.binary', work / 'lazygit')
    (work / 'Dockerfile').write_text('FROM scratch\nCOPY hey /application/hey\nCOPY lazygit /application/lazygit\nUSER 65532\nCMD ["/not-executed"]\n', encoding='utf-8')
    (work / '.dockerignore').write_text('**\n!Dockerfile\n!hey\n!lazygit\n', encoding='utf-8')
    run_command(['docker', 'build', '--platform', 'linux/amd64', '--iidfile', str(work / 'image.id'), str(work)], work / 'build.log')
    run_command(['docker', 'image', 'save', '-o', str(work / 'image.tar'), (work / 'image.id').read_text().strip()], work / 'save.log')
    settings = Settings(syft_binary=str(ROOT / '.tools/syft/syft.exe'), registry_hosts=('docker.io',), image_archive=str(work / 'image.tar'))
    catalog, identity = scan_image('docker.io/sbom-creator-benchmark/aggregate:v1', work / 'image.syft.json', settings)
    paths = ['/application/hey', '/application/lazygit']
    singles = [plan(catalog, [path]) for path in paths]
    combined = plan(catalog, paths)
    if any(p['status'] != 'PLANNED' for p in singles) or combined.get('reason') != 'aggregate_binary_budget':
        raise ValueError('Aggregate experiment differs')
    report = {'experiment': 'R47', 'single_target_plans': singles, 'combined_plan': combined,
              'image_config_digest': identity['image_config_digest'], 'content_scans_started_for_combined': 0,
              'runtime_changed': False, 'direct_accuracy': None,
              'limitation': 'Tighter resource bound makes this multibinary case wholly UNKNOWN; coverage tradeoff, not an accuracy improvement'}
    atomic_json(ROOT / 'docs/go-payload-aggregate-v1.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

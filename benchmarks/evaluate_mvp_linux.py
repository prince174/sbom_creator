"""Post-only packaged-component score of the installed Linux service image."""
import json

from evaluate_mvp_runtime import evaluate_boot, sha
from evaluate_trivy_payload_bridge import projected, read
from run import ROOT, atomic_json

from sbom_creator.validation import validate_cyclonedx


def main():
    output = ROOT / 'benchmarks/results/mvp-container-r105-v1/final-smoke'
    if (output / 'evaluation.json').exists():
        raise FileExistsError('Preserve completed evaluation')
    run = read(output / 'run.json')
    if (run.get('exit_code') != 0 or run.get('reference_sbom_mounted') is not False
            or run.get('repository_mounted') is not False):
        raise ValueError('Completed image-only prediction without oracle required')
    analysis = output / 'workspace/analysis'
    for view in ('final', 'os', 'full'):
        validate_cyclonedx(read(analysis / (view + '.cdx.json')))
    provenance = read(analysis / 'provenance.json')
    if provenance.get('source_kind') != 'not-provided':
        raise ValueError('Unexpected repository input')
    # Oracle access begins after the installed pipeline and every SBOM complete.
    pair = ROOT / 'benchmarks/references/paired-spring-petclinic-v1'
    result = evaluate_boot(pair, {'analysis': analysis, 'provenance': provenance})
    owner = 'pkg:maven/org.springframework.samples/spring-petclinic@4.0.0-SNAPSHOT'
    actual = projected(read(analysis / 'final.cdx.json'), '/application/', owner)
    previous = projected(read(ROOT / 'benchmarks/results/trivy-only-payload-v1/boot/final.cdx.json'),
                         '/application/', owner)
    result.update(runtime_changed=True, runtime='installed Linux container',
                  source_input=False, acceptance=False,
                  image_id=run['image_id'], seconds=run['elapsed_seconds'],
                  output_sha256={view: sha(analysis / (view + '.cdx.json')) for view in ('final', 'os', 'full')},
                  runtime_summary=read(analysis / 'summary.json'),
                  java_image_status=provenance['image'].get('java_image_status'),
                  prior_benchmark_coordinate_delta={'added': sorted(actual - previous),
                                                   'removed': sorted(previous - actual)},
                  limitations=['One disclosed Spring Boot repository, not language-wide production acceptance',
                               'Local immutable archive acquisition, no registry transport or HTTP exercised here',
                               'Original source/build direct graph not supplied and not inferred from image',
                               'Packaging-added UNKNOWN remains conservatively charged FP',
                               'Installed Linux tool output can differ from Windows benchmark inventory'])
    atomic_json(output / 'evaluation.json', result)
    print(json.dumps({'components': result['components'], 'versions': result['versions'],
                      'coordinate_delta': result['prior_benchmark_coordinate_delta']}))


if __name__ == '__main__':
    main()

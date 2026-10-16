"""Use separate R108 namespaces with the existing lossless evidence packer.

Default dry-run never writes. Pack only after every R108 output is complete;
older manifests, packed objects and exact-path ignore blocks stay separate.
"""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('archive-metadata-inspection-r108-v1', 'public-java-hash-research-r108-v1',
                      'mvp-r108-v1', 'mvp-r108-container-v1', 'mvp-r108-js-publish-v1',
                      'mvp-r108-default-parity-v1', 'reactor-packaged-scope-r108-v1')
    evidence.MANIFEST = evidence.RESULTS/'mvp-r108-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS/'mvp-r108-packed'
    evidence.BEGIN = '# BEGIN R108 exact packed-evidence originals (package_mvp_r108.py)'
    evidence.END = '# END R108 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

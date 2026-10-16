"""Use the existing lossless evidence packer for separate R107 namespaces.

Default dry-run never writes. Run pack only after all R107 outputs are complete;
R105/R106 manifests, packed objects and ignore blocks remain separate.
"""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('mvp-r107-v1', 'mvp-r107-directory-diagnostic-v1',
                      'micro-missing-diagnosis-r107-v1', 'mvp-r107-container-v1',
                      'mvp-r107-js-publish-v1', 'reactor-scope-audit-r107-v1')
    evidence.MANIFEST = evidence.RESULTS/'mvp-r107-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS/'mvp-r107-packed'
    evidence.BEGIN = '# BEGIN R107 exact packed-evidence originals (package_mvp_r107.py)'
    evidence.END = '# END R107 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

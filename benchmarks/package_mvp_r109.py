"""Lossless R109 evidence packaging; older attempts stay independently reproducible.

Default dry-run never writes. Do not pack until every listed namespace is final;
the original bytes remain local and content-addressed gzip is verified on restore.
"""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = (
        'js-installed-owner-audit-r109-v1', 'mvp-js-types-r109-v1',
        'mvp-r109-container-v1',
        'reactor-packaged-nested-r109-v1', 'reactor-packaged-nested-r109-v2',
        'reactor-packaged-nested-r109-v3', 'reactor-packaged-nested-r109-v4',
        'reactor-packaged-evaluation-r109-design-v1',
        'reactor-packaged-evaluation-r109-v1', 'reactor-packaged-evaluation-r109-v2',
        'reactor-packaged-evaluation-r109-v3', 'mvp-r109-java-publish-v1',
        'mvp-r109-summary-v1',
    )
    evidence.MANIFEST = evidence.RESULTS / 'mvp-r109-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS / 'mvp-r109-packed'
    evidence.BEGIN = '# BEGIN R109 exact packed-evidence originals (package_mvp_r109.py)'
    evidence.END = '# END R109 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

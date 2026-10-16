"""Lossless R110 default-adoption evidence pack; default dry-run never writes."""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('mvp-r110-held-controls-v1', 'mvp-r110-container-v1',
                      'mvp-r110-js-publish-v1', 'mvp-r110-summary-v1')
    evidence.MANIFEST = evidence.RESULTS / 'mvp-r110-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS / 'mvp-r110-packed'
    evidence.BEGIN = '# BEGIN R110 exact packed-evidence originals (package_mvp_r110.py)'
    evidence.END = '# END R110 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

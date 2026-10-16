"""Lossless R111 cold-cache evidence; default dry-run never writes."""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('public-java-db-validation-r111-v1', 'java-db-peer-regression-r111-v1',
                      'mvp-r111-cold-cache-v1', 'mvp-r111-cold-cache-v2', 'mvp-r111-summary-v1')
    evidence.MANIFEST = evidence.RESULTS / 'mvp-r111-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS / 'mvp-r111-packed'
    evidence.BEGIN = '# BEGIN R111 exact packed-evidence originals (package_mvp_r111.py)'
    evidence.END = '# END R111 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

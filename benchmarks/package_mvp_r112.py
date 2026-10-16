"""Lossless R112 new-public-DB component evidence; default dry-run never writes."""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('mvp-r112-db-export-v1', 'mvp-r112-native-path-v1',
                      'mvp-r112-native-path-v2', 'mvp-r112-java-v1', 'mvp-r112-evaluation-v1',
                      'mvp-r112-container-v1')
    evidence.MANIFEST = evidence.RESULTS / 'mvp-r112-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS / 'mvp-r112-packed'
    evidence.BEGIN = '# BEGIN R112 exact packed-evidence originals (package_mvp_r112.py)'
    evidence.END = '# END R112 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

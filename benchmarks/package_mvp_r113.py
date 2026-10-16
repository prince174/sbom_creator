"""Lossless R113 publication evidence; default dry-run never writes."""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('mvp-r113-chalk-history-v1', 'mvp-r113-native-publication-v1',
        'mvp-r113-native-publication-v2', 'mvp-r113-publication-v1', 'mvp-r113-container-v1')
    evidence.MANIFEST = evidence.RESULTS/'mvp-r113-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS/'mvp-r113-packed'
    evidence.BEGIN = '# BEGIN R113 exact packed-evidence originals (package_mvp_r113.py)'
    evidence.END = '# END R113 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

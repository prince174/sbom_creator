"""Package R106 evidence with the existing lossless gzip/SHA256 contract.

Run without arguments for a read-only dry run.  R105 namespaces, manifest,
packed objects and exact-path gitignore markers are never selected or replaced.
Only run ``pack`` after every R106 prediction and evaluation has completed.
"""
from __future__ import annotations

import package_mvp_evidence as evidence


def configure():
    evidence.NAMES = ('mvp-r106-v1', 'mvp-r106-container-v1', 'mvp-r106-container-scratch-v1',
                      'mvp-r106-container-final-v1', 'chalk-publish-diagnostic-v1',
                      'mvp-r106-selector-parity-v1', 'mvp-r106-selector-parity-v2',
                      'mvp-r106-container-selector-v1')
    evidence.MANIFEST = evidence.RESULTS/'mvp-r106-evidence-manifest.json'
    evidence.PACKED = evidence.RESULTS/'mvp-r106-packed'
    evidence.BEGIN = '# BEGIN R106 exact packed-evidence originals (package_mvp_r106.py)'
    evidence.END = '# END R106 exact packed-evidence originals'


def main():
    configure()
    evidence.main()


if __name__ == '__main__':
    main()

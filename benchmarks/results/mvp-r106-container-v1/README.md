# R106 installed-container checks

These namespaces preserve distinct attempts; no completed prediction was
overwritten. No deployed service was changed and no Docker image was pushed.

## Original attempt and diagnosed failure

`mvp-r106-container-v1` freezes the pre-selector experimental v5 source/data,
Microservices image archive and public scanner Java DB before prediction. The
service image built successfully with unchanged source hashes. The installed
image-only pipeline failed at `image_scan` after 79.24 seconds and published no
SBOMs; this is not an accuracy success.

`syft-tmp-diagnostic/result.json` establishes the cause with pinned Syft only:
the 512 MiB `/tmp` filesystem reached zero free bytes, and Syft reported
`unable to populate layer cache` followed by `no space left on device`. This
diagnostic mounted only the controlled image archive, without secrets or a
reference SBOM. The failure was not attributed from a generic RuntimeError.

## Configuration-only experimental pipeline

`../mvp-r106-container-scratch-v1` retains the same frozen image, classifier,
archive, DB, memory/CPU limits and logical resource budgets. Its only effective
configuration change is `TMPDIR`, `TMP` and `TEMP` pointing to a pre-created
`/workspace/process-temp`; the separate `/tmp` limit remains 512 MiB.

The actual installed Linux pipeline completed in 517.271 seconds, including
fresh Syft/Trivy scans and physical verification; the surrounding harness took
524.484 seconds. This includes Windows Docker Desktop bind-mount I/O. All three
SBOM schemas passed. Final/full contain 1,878 component instances, OS contains
zero, and 111 decisions remain UNKNOWN. These are counts, not accuracy metrics.
The corresponding coordinate multisets exactly equal the completed Windows
prediction in all three views. All 16 exports retain verified hashes; large
JSON files are losslessly compressed with gzip.

The physical reader normalized 1,303,884,800 bytes once, used 89,841,178 payload
read bytes and 1,952,538,302 full-verification read bytes, and checked CRCs for
1,267 stored nested windows. It recorded 1,165 class witnesses and 26 resource
witnesses, with zero reader rejections. These observations establish neither
dependency directness nor accuracy against a reference.

The 80 Docker cgroup samples reached an observed maximum of 571 MiB under a
3 GiB memory limit. This is not measured peak RSS, a hard disk quota proof, or
acceptance under a 2 GiB limit.

The measured pre-selector v5 implementation remains an **experimental** result.
The parent evaluation found a precision/recall tradeoff, so it was not enabled
as the service default. Exact old check/helper source snapshots are retained
in both completed namespaces.

## Shipping selector and defaults

`../mvp-r106-container-selector-v1` records the final
`sbom-creator:mvp-r106-final` build and installed configuration check. Image ID:
`sha256:ce5737b1915804d33f6c335a3b13f01e6a61da319ff64beba0b70b57dbc55613`.
All 43 installed source/data files match the new frozen snapshot. The stable
reader is selected by default; `SBOM_JAVA_NESTED_WINDOWS=true` explicitly selects
the experimental reader, whose source bytes exactly equal the measured
algorithm. Tool binary hashes also match the experimental run.

Default process scratch is now `/workspace`, which is already required and
writable. The installed check verified default-false and explicit-true selector
parsing, invalid-value rejection, writable scratch/cache/image-temp paths,
read-only HOME, non-root UID 10001, and unchanged 512 MiB `/tmp`. The full
nine-minute Microservices run was not repeated after this selector-only move.
The parent separately checks cached-input publisher and physical parity.

`../mvp-r106-container-final-v1` retains the earlier pre-selector ENV-only build;
its image is preserved as `sbom-creator:mvp-r106-preselector-env`. The original
experimental image remains `sbom-creator:mvp-r106`.

The reusable smoke/check scripts now record requested mode and accept an
explicit `--nested-windows`; omission keeps the stable default. Frozen old
pre-selector attempts must be reproduced from their saved snapshots rather
than silently treating them as default-mode runs.

# R111 warm Java DB / raw Trivy peer parity

This integration regression called only the actual current `runtime.peer` using
two existing image archives and the pinned public database. Syft, image
acquisition, physical archive corroboration and publisher entry points were
forbidden. No source/project build, reference label or evaluator was invoked.

All 48 current source/schema files, tool bytes, public DB/metadata, input image
archives and previous R110 raw peer catalogs were frozen before importing the
snapshot or scanning. Bytecode generation was disabled before snapshot imports.
Every source and input hash was rechecked after both serial image scans.

| Case | Raw component instances | Current peer time | Warm cache validation time | Raw identity/path/layer/config parity |
| --- | ---: | ---: | ---: | --- |
| Petclinic REST | 252 | 4.703 s | 2.500 s | Exact |
| Commons DBCP | 4 | 4.125 s | 2.500 s | Exact |

Comparison preserves duplicate component instances. It includes type, group,
name, version, PURL and **every** producer component property, including exact
FilePath, LayerDiffID and LayerDigest; image config identity also matches. Dynamic
SBOM timestamps and generated reference IDs are not component-identity changes.
Equal raw counts alone were not used as proof.

The new atomic cache helper was actually called once per image. Both calls
returned `reused`, without network download or refresh. The existing 1,553,915,904
byte database remains SHA256
`c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25`.
Its metadata bytes also remain unchanged. Public metadata Version 1 and stale
state are recorded in each run; this cache was not stale at the measurement time.

Schema/index/PK validation and full file hashes do not claim complete SQLite
integrity or publisher authenticity. This is a warm-cache wiring/determinism
check, not cold-download, concurrency, hard quota, process RSS or new component
accuracy acceptance. Previous final/OS/full and accuracy results remain in R110.
Raw newly produced peer SBOMs are retained alongside `freeze.json` and reports.

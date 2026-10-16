# R110 release-default held controls

Both controls used existing immutable image archives and the actual service in
image-only mode. Syft 1.51.1, Trivy 0.75.0, physical reads and publication were
fresh and serial. There was no repository/source input, build, reference cache,
classifier tuning or archive-component flag override. `Settings()` selected the
new true default and Java policy `image-delivered-archive-v7`.

The controls were historically disclosed and held from recent Java reader and
identity tuning. They are **not fresh blind acceptance samples**. Both predictions
and all six final/OS/full documents completed before the separate evaluator
opened any reference or packaging label.

| Control | Project TP / FP / FN | Precision | Recall / exact version coverage | Conditional version accuracy | Time |
| --- | --- | ---: | ---: | ---: | ---: |
| Petclinic REST | 104 / 3 / 2 | 97.196% | 98.113% | 99.048% | 26.938 s |
| Commons DBCP | 3 / 0 / 0 | 100% | 100% | 100% | 7.516 s |
| Micro aggregate | 107 / 3 / 2 | 97.273% | 98.165% | separate per-project values above | — |

Aggregate F1 is 97.717%; repository macro precision/recall/F1 are
98.598%/99.057%/98.826%. The held known-delivered component checks exceed 90% for
each project. This is not a universal accuracy or complete shaded-scope claim.

REST retains two missing identities: Hibernate core namespace and Hibernate
models version. The corresponding wrong predictions and packaging-added
jarmode-tools remain three conservative FP. Count delta is +1. DBCP is exact
with delta zero. No mismatch was filtered away using the reference.

Whole inventory final/OS/full counts are REST 109/143/252, DBCP 4/0/4. The root
artifacts and OS are retained. Project scoring uses the controlled
`/application/` scope. REST has six UNKNOWN evidence groups and remains partial;
DBCP has none. The image-only direct graph remains UNKNOWN: 24 known direct
edges are FN and do not become component claims.

REST labels are the existing controlled resolved/nested SHA256 packaging labels,
checked against the immutable receipt and reverified actual application TAR and
OCI/config bindings. DBCP delivered dependency labels are actual regular-file
SHA256 joined to controlled CycloneDX hashes. Its own primary is independently
excluded through effective/native/CDX agreement, literal controlled copy,
canonical embedded metadata and complete physical SHA256.

Resource details and evidence coverage are in
`resource-and-evidence-coverage.json`. Neither held control produced a
metadata-only `verified_archive_component` proof: all included JARs have
class/resource evidence. These controls validate default-v7 integration but do
not independently establish metadata-only archive generalization. R108's
disclosed real proofs and adversarial tests remain a separate evidence stratum.

The first evaluator preflight stopped before oracle access: the original runner
copied 47 source/schema files, then imported them before recording hashes, so the
immutable freeze includes 22 additional generated cache files. That failure and
exact evaluator source are preserved. No scan was rerun and no freeze changed.
`portable-source-binding.json` lists the 47 mandatory source/schema hashes;
`generated-bytecode-evidence.json` preserves exact 22 ancillary cache byte
sequences as inert base64 plus SHA256. The evaluator never restores or executes
them. If a local cache file exists its hash must match; missing cache files are
validated from lossless evidence. Missing source files still fail validation.

All original 69 freeze entries were checked. Future runner source freezes the
47 source/schema files before imports and disables bytecode writing. The original
`executed-runner.py` and freeze remain unchanged. `evaluation-binding.json` seals
the successful evaluator and evaluation separately.

No hard disk quota, safe concurrency, cold public-DB download or process peak RSS
acceptance is inferred. Timings include fresh local-archive scans, physical reads
and publisher, but exclude registry acquisition.

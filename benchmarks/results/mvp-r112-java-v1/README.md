# R112 six-image prediction set

Six existing immutable Java images were processed sequentially with the current
service (`88de091`), default archive-component policy v7, and the separately
exported public Java DB. No application build or registry acquisition occurred.

- Cached inputs: original Syft 1.51.1 image inventories, empty-source catalogs,
  local image archives.
- Fresh work: offline Trivy 0.75.0 image inventories, actual physical archive
  reads, identity/payload/archive gates, and the actual service publisher.
- No source repository, commit, reference labels, reference build cache or oracle
  input was supplied to the predictor. No DB download was permitted.
- Defaults: `java_archive_components=true`, `java_nested_windows=false`; no
  enabling override. Optional source backend remained disabled.
- All 48 source/schema files, tool binaries, original catalogs, image archives
  and public DB/metadata were frozen before any prediction.

| Case | Status | Fresh Trivy / physical / publisher seconds |
| --- | --- | ---: |
| microservices | completed | 118.953 |
| boot | completed | 19.031 |
| javalin | completed | 13.954 |
| dropwizard | completed | 86.797 |
| rest | completed | 20.781 |
| dbcp | completed | 7.094 |

Total case time: 266.610 seconds. This excludes cached Syft scans, image
acquisition, downloads and freeze preparation; it is not a clean scanner-only
benchmark or a Linux-versus-Windows performance comparison.

All 96 analysis outputs and 18 final/os/full schema-valid SBOMs were sealed
before the separate POST-only evaluator was authorized. The completion marker
also rechecks all frozen source/tool/database/image/catalog hashes. Zero cases
failed. Raw inventories, actual observed payload, identity/archive proofs,
resource counters and partial/UNKNOWN summaries remain beside each case.

Public DB SHA256:
`491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59`.
Metadata SHA256:
`40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2`.
Every runtime job reported validated reuse and download time zero. The prior DB
and previous prediction namespaces were retained unchanged.

Prediction freeze SHA256:
`f3e388b13530e65b28c72e1348a2de680e3839d99a568f983e7167716636eac7`.
Completion marker SHA256:
`3e5956bce138b1df96462d17a3dd218e814df1fc4cded6016228be1c184adfd3`.

These six repositories were historically disclosed. This is current-service
compatibility/regression coverage, not a fresh blind sample. Accuracy and
reference scope belong to the separate `mvp-r112-evaluation-v1` namespace.
This explanatory README was added after prediction and changes no sealed output.

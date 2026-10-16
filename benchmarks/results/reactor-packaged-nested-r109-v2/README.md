# R109 post-analysis delivered archive labels

These labels were built from immutable controlled-build CycloneDX SHA256 values
and actual exported/image bytes. No prediction, scanner inventory or classifier
audit was opened to construct truth. Actual build/runtime TAR file trees and the
OCI index/platform/config/DiffID chain were independently checked again.

| Pair | Standalone SHA labels | Nested SHA labels | Primary output attestations | Unknown primary candidates | Unknown nested-content/packaging rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| Javalin | 185 | 0 | 0 | 14 | 0 |
| Dropwizard | 2145 | 0 | 34 | 0 | 1 |
| Petclinic Microservices | 1361 | 1259 | 8 | 0 | 81 |

Counts refer to physical archive instances. Repeated standalone/nested copies of
one GAV do not become separate expected coordinates inside an owner.

Each nested archive label uses the complete physical SHA256 and the parent ZIP
entry CRC. Its coordinate requires one controlled own-module CDX identity or one
globally unique reactor CDX identity. Both GAV and qualified PURL must be unique;
an observed global conflict is not resolved by a local filename or package name.
Every parsed ZIP member is fully hashed and CRC checked. Entry inventories are
stored by complete archive SHA256 and include exact member paths, sizes, hashes
and CRCs. A content-cache reuse happens only after that new physical nested copy
has been completely hashed and parent-CRC checked.

The post-only enumeration limits are separate from runtime policy: 8 GiB total
member reads, 128 MiB outer/32 MiB nested, 2 MiB single ZIP directory, 128 MiB
cumulative directories, two million parsed entries, 200x inflate and depth eight.
The runtime limits and runtime implementation did not change.

Completeness is deliberately narrower than a full component claim:

- Javalin has no recorded effective primary-output SHA256 attestation. All 14
  complete primary candidate files were inspected, but their owner identities
  were not guessed from filenames, manifests, POMs or package namespaces.
- Dropwizard has 34 independently attested primary outputs. One shaded example
  archive exceeds the 2 MiB directory guard, so its internal scope stays UNKNOWN.
  The other 33 delivered-JAR scopes are complete at the archive-file level.
- Microservices has eight attested primary fat JARs. Eight nested packaging-added
  JARs have no unique controlled CDX SHA256 identity. Other UNKNOWN rows retain
  bounded child-enumeration rejections separately from independently proven
  whole nested archive identities. Many older Maven ZIP directory records have
  unsupported Unix mode bits; these stricter evaluator checks are not runtime
  identity failures.
- Every primary has non-nested opaque classes/resources or an unparsed body.
  Complete entry hashes do not identify or exclude shaded dependencies. No full
  component scope was declared complete for any owner on that basis.

`report.json` contains the complete per-owner labels. Pair reports and archive
inventories have SHA256 bindings in `input-manifest.json` and pair reports.
Historical native/CDX agreement scopes and scores are unchanged. A separately
named evaluator may compare frozen final SBOMs with these known delivered
archive sets while keeping unresolved scope visible.

The first attempt is preserved in `reactor-packaged-nested-r109-v1`: it stopped
on Dropwizard's single-directory guard. Version 2 records such cases as explicit
per-primary/per-child UNKNOWN and continues, without increasing the guard.

# R109 Java publisher-only regression

The current 47 runtime/schema files exactly match the source snapshot frozen for
`mvp-js-types-r109-v1`. This regression publishes the four cached R108 prepared
Java source/image/provenance inputs using the real publisher and Syft converter.
Scanner, checkout, acquisition and source resolver entry points are forbidden.
No physical image reader, build reference, evaluator or new accuracy measurement
is involved. Production defaults did not change.

| Case | Whole final / OS / full components | Publisher time |
| --- | --- | ---: |
| Microservices | 2628 / 0 / 2628 | 56.125 s |
| Boot | 95 / 143 / 238 | 6.406 s |
| Javalin | 198 / 0 / 198 | 4.000 s |
| Dropwizard | 2174 / 0 / 2174 | 39.485 s |

All twelve CycloneDX schemas, all twelve component-coordinate multisets and four
selected artifact ID sets match the R108 baselines exactly. Java's policy remains
`image-delivered-archive-v7` despite the global JavaScript policy change. Total
publisher/converter time was 106.203 s; it excludes scanners and acquisition.
Whole inventory counts above are not TP or project-scope accuracy counts.

`freeze.json` pins source, converter, runner and cached inputs before publication;
their hashes were checked again after all four publications. The original R108
inventories, physical archive proofs, observed payload and identity audits remain
in their immutable original namespace.

`held-control-input-locations.json` only locates existing REST/DBCP image inputs
and pre-existing producer image metadata for a later stage. It does not evaluate
or predict those controls, prove their image binding again, or read reference
components. DBCP's old `trivy.json` is source-directory output and must not serve
as image peer evidence.

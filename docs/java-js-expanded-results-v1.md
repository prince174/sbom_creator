# Expansion results v1 — 2026-10-15

Four additional real-build pairs are complete: two Java and two JavaScript. There are now12 primary Java +12 primary JS pairs, plus the separate DBCP Java control:25 total (13Java/12JS). The frozen expansion still has16 pending repositories, eight per language. The target remains20 primary pairs each; pinned candidates are not counted as built. Original20 comparisons retain their fixed sampling definition.

| New pair | Partition | Build-reference components, root excluded | Direct build-reference edges | Max shortest root hop / graph edges | Validation |
|---|---|---:|---:|---|---|
| Commons Configuration2.11.0 |development|22|15|4 /31|Real Maven package, native/effective/CDX root agreement; artifact tree/config/schema |
| Spring Petclinic4.0.0-SNAPSHOT, exact commit |development|106|16|7 /216|Real Spring Boot package; JRE image; isolated health UP; artifact tree/config/schema |
| Pino9.6.0 |holdout|12|11|2 /14|Package build/prune; native npm root versions; isolated logger smoke; no-lock derivative |
| Nest TypeScript starter1.0.0, exact commit |holdout|107|6|8 /191|Actual nest build; native npm root versions; compiled HTTP app smoke; no-lock derivative |

Each source is pinned; tool versions/profiles/declaration/build evidence and immutable reference/image binding are retained. Native npm ls runs with network disabled and agrees with the reference root names/versions and source production declarations. Both JS no-lock derivatives preserve every non-lock app path/mode/link/hash and bind the archive/scanned config. No fresh dependency resolution is performed for these scans. Nest's generic fixture default CMD remains a placeholder; the smoke explicitly starts node dist/main.js. Spring's runtime CMD starts its boot JAR directly. Neither smoke publishes a host port or changes a deployed service.

First unchanged-service results, exact names and versions:

| Pair | Final project components TP/FP/FN | Direct | Interpretation |
|---|---|---|---|
| Commons Configuration |21/1/1, P/R95.45% |UNKNOWN;15 known reference root edges remain unmatched |xml-resolver namespace mismatch is retained |
| Spring Petclinic |Acceptance metrics UNKNOWN; raw build-reference delta retained separately |UNKNOWN |Build-resolved and packaged-image scope need adjudication; confirmed payload/identity failure below |
| Pino, including no-lock |12/1/0, P92.31%, R100% |11/0/0; versions100% |Extra transport test fixture remains visible |
| Nest, including no-lock |106/0/1, P100%, R99.07% |6/0/0; versions100% |Missing @tokenizer/token@0.3.0 is retained |

The compiled Spring Boot JAR is65,830,920bytes. The service's same-scan payload capture/read limit is33,554,432bytes (32MiB); the final project projection confirms zero matching application coordinates. Image scanning itself emits packages, but the service has PAYLOAD_NOT_CONFIRMED and AMBIGUOUS_IDENTITY results. This is not a working >90% Java result. Raw image-to-build-reference set distance is66TP/26FP/40FN; that is a diagnostic distance, not an acceptance runtime accuracy score. Maven starters/POMs, boot devtools exclusions, packaging-added jarmode tools and resource-only JARs must be labelled separately before every difference can be called an error. The limit/identity failures are independently visible without using the oracle as a classifier hint. No unbounded limit increase, alias guessing or policy relaxation was introduced.

Nest also exposed a measurement error risk: raw image inventory has107/0/0, while final service output has106/0/1. The no-lock harness's equality guard initially stopped the run. It now scores final output and retains raw inventory separately. This makes the omission visible; it is not a recognition improvement. Original10 JS no-lock baseline metrics remain unchanged after replay verification. Resume-only timing is labelled separately, not presented as full analysis duration.

[All20 expansion statuses, reference hashes, graphs and measured/UNKNOWN results](../benchmarks/results/expanded-v1/status.json). [No-lock control evidence](../benchmarks/results/no-lock-expanded-v1/). Native trees, smoke logs, candidate provenance and preflight failures are in the expansion results directory. Service source is unchanged from4f29791 and the frozen candidate hashes agree; no rules were tuned on these holdout outputs. A later fix based on a disclosed control requires a fresh independent acceptance control.

Checks:298 tests passed,3 platform skips, known Starlette warning; targeted acquisition/payload tests and Ruff pass. Four new reference schemas and12 service output schemas validate; both derivative three-view schemas and payload/config proofs validate. Peak CPU/RSS were not instrumented; no performance rank is assigned. The partial-clone acquisition problem was preserved and recovered using a full clean upstream checkout. No foreign changes were overwritten.

Next: retain these as regression cases, obtain scoped packaged-reference labels for boot images, implement bounded large/nested/resource-JAR evidence handling with resource/security tests, and continue real module/workspace/Gradle builds from the frozen list. Those strata remain unbuilt gaps, not successes. Continue top-three comparisons on the expanded admitted scopes; previous small-corpus rankings cannot establish general production accuracy.

Boot packaging adjudication (R87, 2026-10-16): the evaluation-only [v3 artifact report](../benchmarks/results/boot-packaging-labels-v3/report.json) confirms92 packaged dependencies (90 class,2 resource),14 absent build artifacts and1 UNKNOWN packaging-added artifact. All106 build artifacts have primary CycloneDX SHA256 labels. Full16 build-direct edges remain separate from9 packaged direct edges. These labels do not repair the service's zero confirmed Boot payloads or establish runtime execution; acceptance remains incomplete. First Javalin reactor build failed on missing build-context .git metadata and does not increase pair counts.

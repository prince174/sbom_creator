## R90 — passive Java image identity comparison, 2026-10-16

Same immutable Javalin image, eight module owners whose CycloneDX/native runtime component sets agree. One development project, not eight independent projects. Six additional shipped owners retain UNKNOWN component scope. No source execution, lockfile or oracle input to either scanner.

| Technique / mode | Exact component TP/FP/FN | Precision / recall | Direct edges | Status |
|---|---:|---:|---|---|
| Trivy0.75.0, offline image + frozen Java DB |128/0/0|100% /100%|UNKNOWN;55 shipped-owner edges unmatched|Strongest of these two measured image identity modes; not integrated |
| Syft1.51.1, same image metadata inventory |109/19/19|85.16% /85.16%|UNKNOWN;55 unmatched|Raw inventory agrees with R89 final coordinate score on these eight owners |
| cdxgen13.4 |Not measured on this same image stratum|Not ranked|External Maven results belong to a different mode|Original-corpus build-enabled success does not establish expanded image-only accuracy |

Exact PURL comparison includes versions; all128 matched owner-component occurrences have correct versions. Macro P/R100% over the eight agreeing positive owners; scope coverage8/14 owners only. No overall production >90% claim. Kotlin/ASM identities causing Syft errors are correctly identified in this Trivy run. Image inventory does not establish directness or payload execution and cannot replace service evidence gating without validation.

Boot cross-check: Trivy finds90/92 hash-labelled packaged dependencies, with3 conservative extras: P96.77%, R97.83%, F197.30%. One extra is UNKNOWN packaging-added jarmode-tools, charged as FP for a lower bound; actual Hibernate group and version discrepancies remain. Application owner excluded, full image retained.16 build-direct edges remain unmatched. Both are disclosed development cases.

[Reactor evidence](../benchmarks/results/trivy-reactor-image-v3/evaluation.json), [same-image raw Syft comparison](../benchmarks/results/trivy-reactor-image-v3/syft-raw-comparison.json), [Boot evidence](../benchmarks/results/trivy-boot-image-v1/evaluation.json). Repeat confirms all200 exact coordinate/path pairs. First license-only run returned zero language files and is invalid for JAR evaluation; first offline SBOM run failed without Java DB. Both negative attempts retained. Public Java DB bootstrap downloaded938MiB, expanded1,553,915,904bytes; frozen SHA256/metadata retained, DB stays in local benchmark cache. Exact-cache replay is reproducible; public tag is mutable and is not an immutable retrieval guarantee. CPU/RSS not measured; no timing rank.22 targeted schema/graph tests passed; Ruff passed. Next: fresh independent positive controls and source+image owner graphs before integration.

# Java / JavaScript: comparison of three techniques

Original fixed20 comparison, 2026-10-15: ten Java and ten JS primary real-build pairs, plus one independent positive Java control. Scores below use exact coordinates and versions; root excluded. No universal cross-mode ranking is assigned.

Expansion: [four new built pairs and observed failures](java-js-expanded-results-v1.md), [frozen20-candidate protocol](java-js-expanded-corpus-v1.md). Current total25 triples (13Java/12JS, including DBCP extra control);16 new candidates pending. Spring Boot large-JAR evidence and image/build scope gaps prevent a general production success claim. The table below remains the original fixed20 result, not an expanded-corpus ranking.

| Technique / mode | Java components and direct TP/FP/FN | JS components / direct TP/FP/FN | Status |
|---|---|---|---|
| cdxgen13.4.0, external native Maven |11/0/0 on10 primary projects; DBCP control3/0/0 |Passive lock-assisted188/0/0 components;86/3/0 direct |Java Maven mode succeeds, requires project tooling; not production-compatible as-is |
| Trivy0.75.0, passive plus scope adapters |7/0/4; optional/fingerprint development supplement11/0/0 |Lock-assisted188/0/0 components;86/0/0 direct on six established positive roots |Passive candidate; JS no-lock engine comparison still pending |
| Syft1.51.1 inventory + service H2.1 declaration/image |9/2/2 components; Java direct unsupported |No-lock service188/8/0 components;85/0/1 direct |Production runtime; JS fixed /app scoring projection, not a generic ownership guarantee |

[Full20-pair passive comparison](java-js-twenty-comparison.md), [external Maven/cdxgen](cdxgen-build-enabled-v1.md), [no-lock service replay](java-js-no-lock-v1.md). Six empty Java and four empty JS roots do not inflate accuracy. JS owner-status coverage9/10; Axios component precision61.54% remains a known weak case. The no-lock service aggregate is P95.92%/R100% components and P100%/R98.84% direct, but independent general ownership validation and Java runtime integration remain open. Do not declare the full production goal complete.

## Historical stages (scope and corpus differ from current results)

**R66 scope correction:** all4 Trivy excess edges and49/52 cdxgen excess edges
are dev-only root declarations. An exploratory manifest-only scope adapter gives
Trivy51/0/0, our saved H2.1 50/0/1, cdxgen51/3/0. This changes the preliminary
ordering, but is not independent control proof. Raw results below remain valid
for their unnormalized modes. [Evidence](npm-competitor-scopes-v1.md).

## R65: image manifest/lock variants, 2026-10-15

Extracted root package.json and package-lock.json from the existing verified
runtime image exports, never from CycloneDX references. Same input files for
Trivy and cdxgen; no project execution or installation. All six generated SBOMs
pass their1.7/1.6 schemas. Input hashes, raw outputs and results are retained in
[the report](../benchmarks/results/npm-image-manifests-v1/summary.json).

| Technique | Koa predicted/reference | Fastify | Hapi | TP/FP/FN | Precision/recall/F1 |
|---|---:|---:|---:|---|---|
| Our declaration/image H2.1 (prior R8/R19) |18/18|14/15|18/18|50/0/1|100%/98.04%/99.01%|
| Trivy0.75.0 image manifest/lock |18/18|18/15|19/18|51/4/0|92.73%/100%/96.23%|
| cdxgen13.4.0 image manifest/lock |23/18|50/15|30/18|51/52/0|49.51%/100%/66.23%|

On this three-project set, preliminary order by direct-edge F1 and false-positive
avoidance is our H2.1, Trivy, cdxgen. Trivy has better recall, so this is a
precision/recall tradeoff, not dominance. Output edge counts include scope
differences relative to the production reference; excess edges are not silently
removed. No general tool ranking or Java result follows from these npm cases.
Our current row is a saved measured baseline, not a new runtime replay.

These image-derived inputs resolve the earlier missing source-lock graphs for
Fastify/Hapi. Raw source-mode R64 failures remain below as separate observations.
No production changes. Next: inspect excess-edge scopes, repeat with normalized
production modes selected without oracle hints, and complete Java comparison.

Priority updated 2026-10-15 at the user's request: Java and JavaScript first.
Other language expansion is deferred. Direct dependencies take priority over
transitive inventory counts. Available verified real pairs: six JavaScript and
two Java; target remains ten projects per priority language.

Three techniques under evaluation: SBOM Creator declaration/image association,
Trivy0.75.0 source graph, cdxgen13.4.0 source graph. Global ranks are not assigned.
Reference build SBOMs are evaluation-only; competitors receive source, with
external project execution denied for cdxgen. This first pass measures source
competitors, not a completed source+image fusion comparison.

| Project / reference direct | Our technique | Trivy | cdxgen |
|---|---|---|---|
| Koa /18 |18 TP,0 FP,0 FN|18 TP,0 FP,0 FN|18 TP,5 FP,0 FN;23 predicted|
| Fastify /15 |14 TP,0 FP,1 FN|Graph UNKNOWN|Graph UNKNOWN|
| Hapi /18 |18 TP,0 FP,0 FN|Graph UNKNOWN|Graph UNKNOWN|
| Gson /1 |Earlier J1 candidate evidence only|Current scan failed: Maven429|No SBOM, child process denied|
| Commons Text /1 |Earlier J1 UNKNOWN|Current scan failed: Maven429|No SBOM, child process denied|

Our npm results are existing R8/R19 measurements, not new scans. The single
Fastify UNKNOWN is pino's unsupported union requirement. UNKNOWN counts as FN
against the known direct reference. Historical Java Trivy2/2 development results
remain valid as historical observations, but do not replace today's failed runs.

On Koa alone, our technique and Trivy tie for closest direct set; cdxgen is third
with five additional root edges. That is not a general Java/JS ranking. The
source-mode cdxgen scope may include development dependencies; differences are
retained, not silently filtered with oracle knowledge. Koa source inventory has
35 npm coordinates for Trivy and363 for cdxgen; these are not direct counts and
not yet normalized to a comparable runtime inventory.

Fastify/Hapi source inputs do not provide usable resolved graphs in these modes.
Zero components with unknown graph is a failure to establish coverage, not a
zero-dependency success. Java Trivy reports Maven Central HTTP429/Retry-After;
no immediate retry or project execution is used to bypass it.

[Raw outputs, logs and summary](../benchmarks/results/java-js-comparison-v1/summary.json)
are retained. Re-evaluation reuses scans; cached timing is null, not zero runtime.
Two graph-adapter tests and Ruff pass. No production or deployed service change.

Reproduce: `python benchmarks/compare_java_js.py`. First scans use the documented
[Trivy filesystem mode](https://trivy.dev/docs/latest/target/filesystem/) and pinned
[cdxgen source](https://github.com/cdxgen/cdxgen/tree/b84786dec587a20deb605192087388fc0604b12d).

Next: use manifests/locks legitimately acquired from each paired image to test
source+image variants; normalize owner and production scope without reading the
reference; expand Java paired projects. Rank only after comparable coverage,
exact identities/versions, TP/FP/FN and count deltas are available.

## R83 update — external Maven mode, 2026-10-15

[cdxgen13.4 with native Maven allowed](cdxgen-build-enabled-v1.md) now produces valid SBOMs on all10 Java development pairs: exact components/direct11/0/0 (four positive roots), plus independent DBCP control3/0/0. This replaces NO_SBOM only for the new build-enabled mode; the previous passive failure remains reproducible. It is the strongest measured ready-made Java result with Maven execution permitted, but is not production-compatible as-is. Keep execution modes separate when choosing a runtime technique. JS lock-assisted scores do not establish no-lock production accuracy.


R88 expansion update (2026-10-16): [Javalin reactor evidence](java-js-expanded-results-v1.md) adds a real19-project build pair, but production service image scanning fails its64MiB output budget. No expanded-corpus winner or changed ranking is established; preserve this failure in coverage.

R89 (2026-10-16): [local-archive metadata/evidence prototype](java-js-expanded-results-v1.md) bypasses Javalin's inline-output overflow with unchanged output/read limits. It is not registry-compatible and does not alter rankings: exact component P/R85.16% on8 agreeing development owners,6 scope-UNKNOWN owners,55 direct edges unmatched. No production integration.

## R91 — owner/direct graph experiment, 2026-10-16

Same Javalin source commit, passive Trivy0.75.0 POM parsing, no Maven/project execution. Distinct POM-path wrappers bind owner refs despite repeated PURLs. Raw offline source:42/0/13 direct edges over14 shipped owners (P100%/R76.36%). Experimental unprofiled-root optional projection:49/0/6 (P100%/R89.09%, F194.23%). Thus the ready image engine's strong component scores do not yet solve direct dependencies. This source projection preserves the original checkout but changes parser input; its component/transitive graph must not be used as truth.4 non-shipped POM owners remain separately reported;18 module-containment extras are still unresolved in full source graph.

[Raw and projected per-owner evidence](../benchmarks/results/trivy-reactor-source-optional-v1/evaluation.json), [candidate freeze](../benchmarks/results/trivy-reactor-source-optional-v1/candidate-freeze.json). Online metadata attempt returned Maven Central429, no score; backoff retained.29 tests and Ruff passed. No runtime integration or independent acceptance. Six unresolved managed versions remain misses, not image-based guesses.

## R92 — direct edges with remote POM metadata, 2026-10-16

Trivy0.75.0 optional-declaration projection plus public Maven metadata now yields55/0/0 exact direct edges on14 shipped Javalin owners: P/R/F1/version accuracy100%, compared with offline49/0/6. All19 predicted source-owner graphs reproduce from another empty HOME/cache. This is one disclosed development repository; no independent acceptance or runtime integration. Across all18 labelled modules the source candidate remains72/18/0 because POM containment relations are still mixed into tool dependencies; those extras are retained separately. Component-scope UNKNOWN for6 owners from R90 remains unresolved.

[Per-owner evaluation](../benchmarks/results/trivy-reactor-source-optional-mirror-v1/evaluation.json), [candidate freeze](../benchmarks/results/trivy-reactor-source-optional-mirror-v1/candidate-freeze.json). Central retry after the prior deadline again returned429; renewed backoff recorded. A separately configured Google-hosted public mirror supplies POM metadata without origin fallback configured. Its lack of an official product SLA and unpinned remote POM responses preclude treating this configuration as a completed production design. First mirror scan about96s; timing includes source scanning/network resolution, not image analysis.32 tests/schema checks pass, Ruff passes. Fresh complex controls, remaining builds and safe production integration are next.

## R93 — first fresh Java control, 2026-10-16

Frozen passive Trivy candidate on newly built Petclinic REST4.0.2: root build compile/runtime direct21/0/0 (P/R/F1/versions100%); packaged components104/3/2 (P97.20%, R98.11%, F197.65%). Matched-identity version accuracy99.05%; exact-version coverage98.11%. One packaging-added UNKNOWN is conservatively charged FP, Hibernate group/version discrepancies remain.106 packaged dependency labels are hash-bound to the real build;15 build artifacts absent from image are separate.12 of21 direct artifacts are packaged,8 starters and1 annotation processor are absent.

[Independent control evaluation](../benchmarks/results/petclinic-rest-frozen-control-v1/evaluation.json), [reference pair](../benchmarks/references/paired-petclinic-rest-v1/receipt.json). This is a single shared Spring Boot stratum, with no optional declarations or reactor; macro=micro for one owner/project and it does not independently validate optional/module adaptations. No candidate tuning on this control. The unchanged service's final output still scores0/0/106 known packaged app components and21 unmatched direct edges; its [three SBOMs](../benchmarks/results/petclinic-rest-frozen-control-v1/baseline-service/) are preserved separately. These candidate scores are not production service accuracy.

27 pairs now exist,15Java/12JS including DBCP;14 complex candidates remain unbuilt. Runtime integration and full control/regression gates remain open.290 tests passed,3 skipped; schemas/hash/native/tree/config checks and isolated HTTP200/health UP passed. No deployed service changed.

R94 acquisition feasibility does not change ranks or accuracy: crane0.22.1 fetched the same Javalin platform manifest from an ephemeral loopback registry without Docker/project execution, then R89 bounded evidence reproduced all three component-coordinate multisets. [Report](../benchmarks/results/registry-archive-bridge-v3/report.json). HTTP fixture only; Windows explicit-CA TLS positive control failed and is [retained unscored](../benchmarks/results/registry-archive-bridge-v2/report.json). Linux trusted-TLS/auth and bounded large/resource JAR proof remain integration gates. Service runtime and27-pair corpus unchanged.

R95 closes the Linux trusted-TLS/auth feasibility gate: isolated non-root/no-network harness validates the exact same config digest, correct credentials, x509 rejection and401 rejection for missing/wrong credentials. [Evidence](../benchmarks/results/registry-tls-linux-v1/harness.json). No insecure TLS flag or runtime Docker requirement. This transport-only result does not change ranks or accuracy; large/resource JAR evidence, adversarial transport cases and runtime integration remain open.

## R107 — opt-in directory-credit LRU experiment, 2026-10-16

Stable default remains R105 policy v4. Explicit `SBOM_JAVA_NESTED_WINDOWS=true`
selects experimental v6. Cached producer catalogs + fresh physical reads + actual
publisher finish all four Java cases before reference access, on unchanged scopes.

| Technique / mode | Current measured result | Scope and status |
|---|---|---|
| Actual service OPT-IN v6, Syft1.51.1/Trivy0.75.0 + bounded directory-credit LRU |Micro124/1/16 vs R10699/1/41; Boot90/3/2, Javalin128/0/0, Drop893/0/14 unchanged. Java micro1235/4/32,P99.677/R97.474; repository macroP98.994/R96.213 |25 new TP, zero removed coordinates/new FP; MicroR88.57 still below90,31 owner scopes UNKNOWN. Disclosed experiment, not default adoption |
| cdxgen13.4.0 + native Maven |Unchanged R104 Micro source100/0/0 shipped direct, raw100/8/0 |Optional source model; not image component inventory or original-CI proof |
| Trivy0.75.0 passive source projection |Unchanged R104 Micro source76/0/24 direct |Optional partial fallback, not a new comparable image score |

R106's actual failure was256 fingerprint credits(742 rejections), below byte/entry
limits. R107 keeps256 live credits, evicts LRU entries and conservatively recharges
evicted directories on reuse. SAME16MiB/100k cumulative budgets; Micro uses9,813,237B,
91,317charged entries,106evictions/362charges, no budget-guard rejection. Earlier
12 unmatched original PURLs were a diagnostic join issue; exact path/layer peers
already had correct GAVs, no alias rule was added. Remaining16 MicroFN are15
metadata-only starters plus netty-common identity UNKNOWN; jarmode stays FP.

501 tests passed,3 skips,20.03s;12 new security cases cover resource/identity
negatives. JS12 cached publisher regressions preserve36views and selected IDs,
84.657s; no fresh JS scans or new accuracy score, original Chalk locking failure
retained. Installed Linux RC with fresh Syft/Trivy scans passes523.962s pipeline/
527.344s harness:44 installed hashes match freeze, final/os/full2458/0/2458 and
2458 selected IDs/all3 coordinate multisets equal Windows. This differs from the
four-case cached-inventory Windows timings; no new independent accuracy/default
adoption claim. Scope-hash availability
audit offers future post-only labels without rebuild; current31 UNKNOWN unchanged.
[Actual results](java-js-service-accuracy.md),
[R107 evaluation](../benchmarks/results/mvp-r107-v1/evaluation.json),
[installed Linux verification](../benchmarks/results/mvp-r107-container-v1/verification.json),
[scope-data audit](../benchmarks/results/reactor-scope-audit-r107-v1/report.json).

## R106 — historical opt-in bounded nested reads experiment, 2026-10-16

Same image inputs and unchanged R105 evaluation scopes, no source/reference in
the classifier. Full16-case snapshot protocol completes before the post-only
evaluator opens any oracle. No new cross-mode or independent ranking is assigned.
Stable default remains the R105 reader. R106 requires explicit
`SBOM_JAVA_NESTED_WINDOWS=true`/`Settings(java_nested_windows=True)`; policy v5 is
experimental only. Measured frozen snapshots are retained unchanged; they do not
establish default production adoption of the precision/recall trade-off.

| Technique / mode | Current measured result | Scope and status |
|---|---|---|
| Actual service OPT-IN policy image-identity-payload-v5: Syft1.51.1 + Trivy0.75.0 + bounded nested windows/CRC + explicit identity gate |Microservices99/1/41 vs R1058/0/132; Boot90/3/2, Javalin128/0/0, Dropwizard893/0/14 unchanged. Java micro1210/4/57,P99.67/R95.50; repository macroP98.94/R91.75 |Experimental final improvement with precision trade-off100→99%; Micro recall70.71 below90 and31 owner scopes UNKNOWN. Not default adoption or global acceptance |
| cdxgen13.4.0 + native Maven |Unchanged R104 Micro source direct100/0/0 on8 shipped owners; raw9 owners100/8/0 |Optional build-model graph, not image inventory or proof of original CI reproduction |
| Trivy0.75.0 passive source projection |Unchanged same Micro source76/0/24 direct |Partial optional source fallback, not ranked as an image component engine |

R106 JavaScript:12 fresh no-lock image-only attempts,11 published. Positive
component metrics unchanged306/9/1,P97.14/R99.67; all three coordinate multisets
of11 published outputs equal R105. Chalk has a retained publication PermissionError;
one separate publisher-only diagnostic succeeds with the same three coordinate
multisets, but does not replace the failed protocol attempt. Empty Chalk is never
precision/recall success. Source/direct UNKNOWN is measured separately.

The opt-in runtime change avoids copying STORED nested JARs into payload-window reads,
validates headers/path/layer plus complete nested-body SHA/CRC, and retains a
bounded16MiB exact-physical-range cache across witnesses. Same128MiB window budget;
Micro consumes91.0MB instead of134.2MB. Remaining41 FN include unresolved bounded
read/identity cases; no reference-derived exclusions or aliases. Final post-selector
suite489 tests passed,3 skips; Ruff. [Full actual service results and failures](java-js-service-accuracy.md),
[R106 protocol](../benchmarks/results/mvp-r106-v1/evaluation.json).
Linux experimental snapshot with workspace scratch passes517.271s pipeline:
final/os/full1878/0/1878, all3 coordinate multisets equal Windows. Original512MiB
`/tmp` ENOSPC failure is retained; shipping scratch configuration is a separate
operational fix and does not enable the nested-window experiment by default.
Final RC selector/configuration smoke verifies43 installed hashes, default=false,
explicit=true/invalid rejection and writable `/workspace` scratch with unchanged
512MiB `/tmp`. Separate selector parity v2 with cached scanner catalogs and fresh
physical reads/publishing passes: opt-in Micro50.766s matches R106 adapted catalog,
physical facts/serialized audit/all3views/selected IDs; default Boot7.890s matches
R105 stable all3views/IDs with policy v4. No new scanner or oracle accuracy run.
The retained v1 negative was a post-publication tuple-vs-JSON-list harness assertion,
not a service/output failure. [Configuration proof](../benchmarks/results/mvp-r106-container-selector-v1/config-smoke.json),
[selector parity](../benchmarks/results/mvp-r106-selector-parity-v2/report.json).

## R105 — historical actual image-first service and separate source graph, 2026-10-16

The current MVP analysis accepts image-only input. Rebuilding an unknown TeamCity
recipe is not required to publish an image SBOM. Optional source-model graphs are
reported separately and never add source-only libraries to final image inventory.
The historical execution bans below are superseded by the user's explicit permission
for isolated cdxgen project-tooling jobs; default source backend remains disabled.

| Technique / fixed mode | New measured result | Scope and status |
|---|---|---|
| Actual service: Syft1.51.1 + Trivy0.75.0 + bounded payload/identity gate |Linux Petclinic final90/3/2 components, P96.77/R97.83; Javalin128/0/0; Dropwizard893/0/14; Microservices8/0/132 on1 agreeing owner |Runtime integration candidate; Microservices payload-budget weakness prevents Java-wide >90 claim. Unknown owner scopes and Windows helper failure retained |
| cdxgen13.4.0 + native Maven |Microservices source direct100/0/0 on8 shipped owners; raw all9 owners100/8/0 |R104 source-model evaluation only, not image accuracy or original-CI reproduction; root module-containment extras remain FP |
| Trivy0.75.0 passive source POM projection |Same Microservices source commit76/0/24 direct;7/9 owner coverage |Partial source fallback; not promoted to native-equivalent recall |

JavaScript12 fresh image-only service scans without project lockfiles: final
components306/9/1, P97.14/R99.67, exact-version coverage99.67%; all12 component sets
equal the previous source-assisted baseline. Axios precision61.54 remains visible.
Image-only direct graphs remain UNKNOWN, not inferred from component presence.
[Actual per-case metrics and failures](java-js-service-accuracy.md),
[R104 source comparison](java-microservices-reference-r104.md).
No universal top-three ranking or global goal completion: these modes have different
tasks/scopes, and the new resource control is weak. Further external build-recipe
expansion is deferred for MVP; existing immutable references remain in regression.

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

R96 bounded disk-backed JAR evidence completes the disclosed Petclinic analysis, but final Syft component identities score only66/26/26 (P/R71.74%, count92 versus reference92);16 known direct edges remain unmatched. [Evaluation and all three outputs](../benchmarks/results/bounded-boot-evidence-v2/evaluation.json). Existing198 Javalin class witnesses are preserved; one resource witness is added, without a directness/use claim. No ranking promotion or runtime adoption. A strict passive Trivy identity-to-path/layer/payload bridge and fresh complex controls remain necessary; raw Trivy inventory scores are still not service final scores.

## R97 — image identity plus bounded payload candidate, development only

Strict same-config/final-path/layer/unique-identity/witness join feeds the existing final/os/full publisher. Petclinic candidate final89/3/3, P/R/F196.74%, conditional version accuracy98.89%, exact-version coverage96.74%, count92/92;16 direct UNKNOWN/FN. Javalin final128/0/0 across the same8 native/CDX-agreeing owners, micro/macro100%;6 scope-UNKNOWN owners and55 direct UNKNOWN/FN remain. No source-owner graph integration, runtime change, independent acceptance or new rank.

[Evaluation](../benchmarks/results/trivy-payload-bridge-v1/evaluation.json), [exact repeat](../benchmarks/results/trivy-payload-bridge-v1/repeat.json), [coverage loss](../benchmarks/results/trivy-payload-bridge-v1/coverage.json). Raw Trivy Boot90/3/2 loses one font-awesome resource JAR at the conservative Syft intersection (final89/3/3); it is explicitly an extra FN, not coverage-neutral integration. Source catalogs/original identities and six SBOMs retained;337 tests pass,3 skips. Next Trivy-only physical resource corroboration, passive source-owner binding and fresh complex controls.

R98 explicitly attributed Trivy-only archive corroboration recovers that FN: candidate final Boot90/3/2, P96.77%/R97.83%/F197.30%, conditional version accuracy98.90%, exact-version coverage97.83%. Javalin128/0/0 over8 agreed owners is unchanged;6 unresolved owner scopes and all16/55 known direct edges remain UNKNOWN/FN. [Evaluation](../benchmarks/results/trivy-only-payload-v1/evaluation.json), [physical/producer audit](../benchmarks/results/trivy-only-payload-v1/boot/supplement.json), [repeat/export attribution](../benchmarks/results/trivy-only-payload-v1/repeat.json). The custom Trivy producer and mandatory physical gate are enabled only in the benchmark, with an explicit experimental policy; runtime remains unchanged.349 tests pass,3 skips. No rank promotion or acceptance; fresh complex reference builds and source-owner integration are next.


R99 adds a fresh complex held-out Dropwizard reference pair:39 reactor/module references,34 shipped JAR owners,443 direct edges;28 total pairs (15 primaryJava/12JS plusDBCP). Frozen Trivy image inventory completes, but passive source resolution times out180s; R98 image payload collection is manually stopped after >23GB observed reads repeatedly processing an over-budget gzip layer. No final outputs/accuracy score or rank promotion. [Negative control and exact evidence](../benchmarks/results/dropwizard-frozen-control-v1/prediction-v1/image-resource-stop.json), [immutable pair](../benchmarks/references/paired-dropwizard-reactor-v1/receipt.json), [details/next gates](direct-dependency-experiments.md). Runtime remains unchanged;13 complex projects remain pending. This control is disclosed for subsequent resource tuning.


R100 (2026-10-16): separate bounded rejection-cache candidate completes Dropwizard final/os/full in94.11s, but confirms no project payload under the unchanged512MiB layer budget. On16 agreeing owners final0/0/907, recall0;18 owner scopes UNKNOWN and443 direct edges unmatched. Boot/Javalin witness/catalog/evidence regression is exact. [Negative evaluation](../benchmarks/results/cached-dropwizard-evidence-v3/evaluation.json), [resource run](../benchmarks/results/cached-dropwizard-evidence-v3/run.json). Benchmark liveness only, no runtime adoption/rank promotion or new pairs.


R101 (2026-10-16): separate seekable-layer prototype verifies the original config/DiffID and reads ZIP headers for2179 physical JAR paths after one703MB normalization (3.69s;2.49MB metadata,8716 target bytes). [Physical-access proof](../benchmarks/results/seekable-layer-index-v3/report.json). New explicit8GiB disk-normalization policy, not a raised frozen payload gate. No class/resource, component/direct accuracy or new SBOM claim; R100 negative metrics/ranks/runtime/corpus unchanged.


R102 actual class/resource corroboration improves disclosed Dropwizard FINAL from0/0/907 to893/0/14 (P100/R98.46) on the same16 agreeing owners;18 scopes UNKNOWN and443 direct FN remain. Boot90/3/2 and Javalin128/0/0 unchanged. JS current no-lock service aggregate306/9/1 components and102/0/1 direct revalidated, with Axios weak case retained. No independent rank promotion/runtime integration: [service/candidate comparison and remaining gates](java-js-service-accuracy.md).


R103 (2026-10-16): benchmark-only explicit identity gate retains confirmed physical facts for rejected identities (Boot/Javalin/Dropwizard1/1/4), while all nine final/os/full coordinate multisets and selected instances remain equal R102. No new accuracy result, ranking change, runtime adoption or pair. [Gate regression](../benchmarks/results/explicit-identity-gate-v2/regression.json). Direct source-owner integration and independent complex controls remain pending.

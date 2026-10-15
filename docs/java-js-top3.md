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

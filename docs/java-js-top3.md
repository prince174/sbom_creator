# Java / JavaScript: comparison of three techniques

**Current20-pair comparison completed:** ten Java and ten JavaScript pairs.
Use [measured results and candidate limitations](java-js-twenty-comparison.md).
JS production-normalized Trivy/cdxgen components188/0/0; Java Trivy7/0/4,
Syft9/2/2, passive cdxgen unavailable. Exploratory Java supplement11/0/0 is
not yet accepted into production. Older staged results below are historical.

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

# Java / JavaScript: comparison of three techniques

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

# JavaScript without project lockfiles, R84, 2026-10-15

All 10 existing JS pairs were replayed through the unchanged service using derivative inputs: source copies omit project lockfiles and .git; derivative runtime images delete only package-lock.json, .package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock/bun.lockb under /app. There is no reinstall, new resolution or execution of project code. Node/npm platform files remain part of the full image inventory.

For each derivative, the exported /app tree must equal the original real-build tree minus lockfiles, including modes, file types, links and file SHA256. OCI archive/index/config binding and scanned config agree. The service final project projection must equal the scored image inventory projection. Three final/os/full SBOM schemas validate for every run. References are read only after analysis. This is an ablation of existing disclosed fixtures, not ten newly independent builds or hidden controls.

| Metric | Exact TP / FP / FN | Micro precision / recall / F1 | Macro over six nonempty roots |
|---|---|---|---|
| Components, root excluded, fixed /app scope | 188 / 8 / 0 | 95.92% / 100% / 97.92% | 92.59% / 100% / 95.52% |
| Production direct edges H2.1 | 85 / 0 / 1 | 100% / 98.84% / 99.42% | 100% / 98.89% / 99.43% |

Coordinates include exact versions. Among matched direct package names, reported version accuracy is 100%; the missing direct dependency remains FN. Owner status is established on 9/10 projects; ms stays UNKNOWN. Its reference has zero direct edges, verified separately; the UNKNOWN does not conceal any known positive edge. Empty cases have null accuracy and do not inflate the means.

Component count is 196 predicted versus 188 reference (delta +8). Axios has 8 TP + 5 FP, precision61.54%; Fastify47 TP + 3 FP, precision94%. The extra app-local packages are test/benchmark fixture manifests, not installed runtime dependencies. They remain in the results; no reference-driven filtering was introduced. Fastify still misses the pino direct relation. No-lock availability therefore does not fix existing scope/ownership weaknesses.

[Per-project results, macro/micro summary](../benchmarks/results/no-lock-v1/summary.json). Each directory contains the derivative Dockerfile, report, payload proof and binding/output-hash proof. Original immutable real-build references are unchanged. Timing is259.31s total for the ten warm local replays including derivative build/export and analysis; peak memory/CPU were not measured. No speed comparison with external Maven/cold tool initialization follows.

Run `python benchmarks/compare_no_lock.py --pair paired-express-v1` for a not-yet-completed fixture; completed evidence is protected. Then `python benchmarks/summarize_no_lock.py` checks all ten bindings and aggregates. The first Express build attempt rejected a raw SHA256 FROM reference; using an explicitly local parent tag resolved Docker's naming issue. No classifier tuning resulted from that preflight failure.

Validation:284 tests passed,3 platform skips, one known Starlette warning; Ruff passed;30 output SBOM schema checks; all ten non-lock payload/binding checks. This stage is a benchmark/verification improvement, not a runtime algorithm change. The >90% general production target is not yet proven: Java runtime integration remains open, JS uses a fixed fixture installation path, and Axios scope precision remains below90%.

Next: freeze a generic manifest/image installation-ownership candidate, verify on a new positive JS control without lockfiles, then integrate only after precision/recall/coverage regression. Continue Java passive fingerprint/native metadata investigation separately from the now-successful external Maven mode.

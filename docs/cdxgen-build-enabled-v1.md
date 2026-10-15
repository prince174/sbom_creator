# cdxgen with external Maven execution, R83, 2026-10-15

The previous Java NO_SBOM results were Node child-process policy failures, not an intrinsic cdxgen limitation. A new external container allows cdxgen 13.4.0 to execute Maven dependency:tree, with runtime scope via MVN_ARGS. No oracle SBOM is mounted. Source is read-only and copied into disposable container storage. No host secrets or Docker socket, all capabilities dropped, no-new-privileges, 2 CPU / 3 GiB limits. The external harness invokes Docker; the service runtime is unchanged.

Pinned base images and the actual tool image digest are in each report/Dockerfile. Actual Node 24.22.0, Maven 3.9.16, Java 17.0.20.1; tool dependency versions are recorded. The package version is published @cdxgen/cdxgen 13.4.0. Full mode here means native Maven resolution is allowed, not that cdxgen recompiles every project. CycloneDX reference artifacts still come from the separately completed real controlled builds.

| Stratum | Projects / positive roots | Components TP/FP/FN | Direct TP/FP/FN | Precision / recall / exact-version identities |
|---|---:|---:|---:|---|
| Existing development corpus | 10 / 4 | 11/0/0 | 11/0/0 | 100% / 100% / all matched |
| Additional frozen positive control, Commons DBCP | 1 / 1 | 3/0/0 | 3/0/0 | 100% / 100% / all matched |

All 11 outputs validate as CycloneDX 1.6; process exits are zero. Six empty development roots have null precision/recall and are excluded from macro accuracy. Positive-root macro precision/recall are 100%. These are small dependency counts, not evidence of broad Java production coverage. Time is wall time, memory/CPU fields are limits, not measured peak usage. First-run caches and separate toolchain versions prevent a fair speed ranking.

[Reproducible per-project reports, commands, logs, tool image digest and summary](../benchmarks/results/cdxgen-build-enabled-v1/summary.json).
Run `python benchmarks/compare_cdxgen_build_enabled.py --run-id replay-01 --pair paired-commons-compress-v1 --image sha256:11e944f4291e284eca333b829e840ce8fac56613744880aff87a9a730fe0d36a` in a fresh evidence namespace (completed reports are immutable). The recorded Dockerfile can rebuild the tool environment; retain/pin the recorded dependency tree and actual image for exact replay. npm transitive ranges are not guaranteed to reproduce identical bytes in a later reinstall.

This is currently the strongest measured ready-made Java method when native Maven execution is permitted. It is not eligible as-is for the production runtime contract, which forbids executing project/build commands. Keep passive Trivy, Syft inventory and optional/fingerprint experiments distinct. No JavaScript no-lock performance follows from these Java results; that ablation is a separate stage.

R83 also freezes explicit IDs for the 20-project development split. Adding a control receipt no longer silently expands, breaks, or contaminates development replays. This is a selection/protocol change, not a classifier rule adjustment after inspecting control results.

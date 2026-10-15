# Expansion corpus v1 — Java / JavaScript

Frozen 2026-10-15 before classifier tuning: 10 additional distinct repositories per language; target20 primary pairs per language. Existing20 primary references and the additional DBCP control remain immutable. Repository metadata/source snapshots are pinned to exact commit SHA, not moving HEAD. PINNED_NOT_BUILT is not a reference pair or an accuracy result.

Each language has six development and four held-out repositories. Root manifests are inspected only to plan build recipes; challenge labels are planned until demonstrated by actual module/profile builds. Candidate source hashes are frozen in the manifest. Do not tune on holdout accuracy; after disclosure/reuse, retire that control from independent acceptance and obtain fresh controls.

| Language | Project | Split | Root declared dependencies / modules | Planned challenges |
|---|---|---|---|---|
|Java|java-commons-configuration|development|31 / 0|optional, exclusions, many-direct|
|Java|java-spring-petclinic|development|28 / 0|spring-boot-app, profiles, dependency-management|
|Java|java-petclinic-rest|holdout|25 / 0|spring-boot-rest, profiles, database-drivers|
|Java|java-dropwizard|holdout|0 / 34|maven-reactor, bom, modules|
|Java|java-vertx-web|development|8 / 10|maven-reactor, modules, optional|
|Java|java-jib|development|Gradle / 0|gradle-multimodule, plugins|
|Java|java-okhttp|holdout|Gradle / 0|gradle-kotlin, multiplatform, modules|
|Java|java-resilience4j|holdout|Gradle / 0|gradle-multimodule, optional-integrations|
|Java|java-javalin|development|1 / 8|maven-reactor, kotlin-java, profiles|
|Java|java-petclinic-microservices|development|0 / 8|multiple-services, spring-bom, profiles|
|JavaScript|javascript-pino|holdout|11 / 0|many-direct, transport, dev-runtime|
|JavaScript|javascript-http-server|development|14 / 0|cli-app, many-direct|
|JavaScript|javascript-fastify-cli|development|13 / 0|cli-app, plugins, dev-runtime|
|JavaScript|javascript-nest-starter|holdout|6 / 0|typescript-build, peer, application|
|JavaScript|javascript-nest|development|19 / 0|monorepo, peer, typescript-build|
|JavaScript|javascript-eslint|holdout|30 / 0|workspaces, cli-app, optional|
|JavaScript|javascript-vite|development|0 / 0|pnpm-workspace, typescript-build, native-optional|
|JavaScript|javascript-verdaccio|holdout|0 / 0|monorepo, plugins, application|
|JavaScript|javascript-sveltekit|development|0 / 0|pnpm-workspace, peer, application-build|
|JavaScript|javascript-next|development|0 / 0|pnpm-workspace, native-optional, framework-build|

Admission and evaluation protocol:

- Build actual application/library/package artifacts from the exact commit; generate CycloneDX within that controlled build, retain native resolved graphs, effective configuration, active profiles, tool/platform versions and final image binding. Preserve failed builds and unscored/missing module graphs.
- For monorepos/reactors, do not score an empty root as success: identify every shipped module/workspace owner and validate its direct edges against native resolution and declarations. Aggregate components are not direct labels. Profile variants and modules are not new independent projects.
- Java coverage includes Spring applications, Maven reactors, dependency management, optional/provided/test/runtime and Gradle/Kotlin. JS covers CLI/server applications, TypeScript compilation, npm/pnpm workspaces, peer/optional/native packages. Unsupported cases stay UNKNOWN.
- Verification has a separate oracle input after prediction. Production inputs remain source+commit+image. Test both lock-assisted and source/image project-no-lock variants; no live reinstall for a no-lock scan. Preserve final/os/full and platform inventory.
- Compare the same three techniques on identical owner/scope/input strata, including passive and external build-enabled modes separately. Report TP/FP/FN, exact versions/edges, count delta, per-project/module and language micro/macro, owner coverage/UNKNOWN and worst cases; failures are not excluded to improve scores.
- Report dependency-count/graph-depth distributions and ecosystem families. Root empty graphs are unscored. Small dependency counts cannot establish the overall >90% goal. Require positive independent control and show module/workspace/Gradle coverage separately; an unbuilt stratum is a gap.
- CPU/memory/time/build limits are explicit. Very large projects may need a dedicated staged recipe; a resource-limit failure remains visible rather than silently replacing the project.

[Frozen manifest and candidate hashes](../benchmarks/java-js-expanded-v1.json). Build receipts and live progress are recorded separately so the frozen sampling definition does not change after results. Runtime classifiers are unchanged at this sampling stage.

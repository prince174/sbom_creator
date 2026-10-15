# Twenty-pair comparison, 2026-10-15

Ten real Java and ten real JavaScript reference pairs are now complete. Every
pair uses exact-commit source, real build CycloneDX, matching library/application
image tree, verified image identity and three validated service output schemas.
Java fixtures are library artifact images without a JRE, not running web apps.
Twenty Java/JS pairs do not yet cover all production profiles/workspaces.

All40 source/image-manifest competitor attempts are saved in
[raw results](../benchmarks/results/java-js-twenty-v1/summary.json).
Thirty SBOMs validated:20 Trivy1.7 and10 cdxgen1.6. Ten Java cdxgen attempts
produced no SBOM under the no-project-execution constraint; unavailable, not
zero dependencies. Both tools are pinned: Trivy0.75.0, cdxgen13.4.0 commitb84786d.

Component metrics compare exact ecosystem/namespace/name/version, exclude the
root application consistently and recursively traverse nested CycloneDX components.
An earlier shallow component traversal undercounted nested reference packages;
the evaluator is corrected and a nested-component regression test added. Earlier
component totals178 are superseded by188 for JavaScript. Direct counts unchanged.

| Technique / component scope | Java TP/FP/FN | Java P/R | JS TP/FP/FN | JS P/R |
|---|---|---|---|---|
| Syft image + known fixture application path |9/2/2|81.82%/81.82%|188/8/0|95.92%/100%|
| Trivy source Maven / npm image manifests + production lock adapter |7/0/4|100%/63.64%|188/0/0|100%/100%|
| cdxgen passive source / npm image manifests + same adapter |Unavailable|Unavailable|188/0/0|100%/100%|

Syft's path projection is experimental fixture scoping, not the production final
SBOM. Whole-image inventory remains intact, including platform packages. Npm
competitor component scope uses the image lock's non-dev entries; direct scope
excludes root dev-only declarations. No filtering uses reference coordinates.
Empty cases have null metrics and do not inflate the totals. Java positives are
four projects/11 edges; JS positives six projects/188 component identities.

Direct graph: Trivy Java7/0/4; JS86/0/0 on6established nonempty roots, four empty
source wrappers remain GRAPH_UNKNOWN. cdxgen JS86/3/0 (P96.63%,R100%), Java unavailable.
Our saved/current npm H2.1 has85/0/1 on six positive roots; ms owner remains UNKNOWN.
Java production direct classification remains unsupported. A full global ranking
is therefore premature; these are measured modes with explicit coverage.

## Exploratory Java optional/fingerprint supplement

Trivy omits four optional Commons Compress dependencies. A separate experiment
reads explicit root optional compile/runtime declarations and local properties,
then checks actual image JAR evidence. Two canonical coordinates already agree
with the image. ASM and XZ incorrect namespace claims are resolved using the
actual JAR SHA256 against the explicit Maven coordinate's repository checksum,
not alias guessing. Input JARs are read from the existing verified image export;
no application execution and no reference input to prediction.

[Evidence](maven-optional-fingerprint-v1.json): supplemented Trivy11/0/0 for Java
components and direct declaration candidates. This is100% on the disclosed small
development corpus, not independent-control evidence or production integration.
Repository SHA256 trust, explicit local declarations, supported scopes and
private artifact access remain limitations. Missing fingerprints stay UNKNOWN.
Candidate evidence does not prove runtime execution.

Current best next candidate is the Trivy+image/declaration/fingerprint combination,
with npm production-scope normalization. Do not declare the user's >90% service
goal achieved: production still needs guarded integration, positive independent
Java control and full service regression. Raw failures and previous metrics stay
available; no known case is dropped to meet the threshold.

Validation:275 service tests passed,3 platform skips, known Starlette warning;
30 competitor schemas; graph/nested-component/count/optional parser tests and Ruff.
Next: freeze this candidate, obtain independent positive control, integrate with
bounded network/file/error behavior, then replay production/verification modes
and preserve final/os/full outputs.

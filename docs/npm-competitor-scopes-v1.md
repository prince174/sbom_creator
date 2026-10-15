# R66: scope differences change the npm comparison

Date: 2026-10-15. Exploratory evaluation, not runtime adoption.

All four R65 excess Trivy root edges are dev-only declarations in the runtime
image's root package.json. Of cdxgen's52 excess edges,49 match dev-only root
declarations and three are not root-declared. Thus R65 measures excess against
production scope, not necessarily incorrect declaration discovery.

A separate exploratory adapter excludes only root names declared in
devDependencies but absent from dependencies/optionalDependencies. It uses the
image manifest before opening the oracle. Unmatched root edges remain; reference
knowledge is never used to remove them. Scope-normalized totals:

| Technique | TP/FP/FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|
| Trivy + root dev-only adapter |51/0/0|100%|100%|100%|
| Our existing H2.1 baseline |50/0/1|100%|98.04%|99.01%|
| cdxgen + same adapter |51/3/0|94.44%|100%|97.14%|

This changes the exploratory ordering on these disclosed three projects, not
the global winner. It is a newly evaluated adapter after inspecting failures,
not independent holdout evidence; compare on a fresh set before adoption.
Raw R65 results remain preserved. Trivy's include-dev-deps flag defaults off,
yet these particular root edges still exist in its generated graph; no claim
that the flag alone fixes them is made.

[Per-edge evidence and normalized counts](npm-competitor-scopes-v1.json).
Run `python benchmarks/audit_npm_competitor_scopes.py`; Ruff passes. No scanner
rules, runtime service or inventory outputs changed. Next: new comparable Java/JS
projects and independent normalized-mode evaluation, plus external result-vs-build
reference verification tooling requested by the user.

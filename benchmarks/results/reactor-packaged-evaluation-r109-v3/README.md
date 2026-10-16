# R109 current packaged view: label v4, frozen R108 predictions

This is a **post-only reference-scope improvement**, not a new Java prediction or
runtime accuracy gain. It compares the immutable R108 actual service final SBOMs
with independently constructed delivered standalone/nested JAR SHA256 labels.

| Reactor | Owners | TP / conservative FP / FN | P | Known-delivered recall | F1 |
|---|---:|---:|---:|---:|---:|
| Microservices | 8 | 1341 / 12 / 8 | 99.113% | 99.407% | 99.260% |
| Javalin | 14 | 184 / 0 / 1 | 100% | 99.459% | 99.729% |
| Dropwizard | 34 | 2140 / 2 / 5 | 99.907% | 99.767% | 99.837% |
| Micro aggregate | 56 | 3665 / 14 / 14 | 99.619% | 99.619% | 99.619% |

Known delivered sets are unchanged from label v3. Only 14 Javalin primary roots
now have independently proved owner scope. The proof binds the immutable literal
Docker copy recipe, effective/native/CDX owner and finalName, complete actual image
SHA256, unique canonical embedded Maven properties, config and DiffID. It rejects
dependency-copy collisions. No primary is excluded by a filename alone. An exact
physical **and** non-nested virtual path is required to exclude the own root; a
nested same-PURL library or ambiguous multi-location observation remains eligible.

Every final Maven GAV under the controlled owner prefix is retained for scoring;
there is no filtering by expected names, reference SHA or matched reference paths.
Microservices retains eight packaging-UNKNOWN jarmode-tools predictions as
conservative FP plus four Hibernate namespace errors. All 14 known-component FN
remain, including Netty, Hibernate, Jdbi, Woodstox and Handlebars observations.

Exact-version coverage against the known delivered GAVs equals recall; conditional
matched-identity version accuracy is 100%. Repository macro P/R/F1 is
99.673% / 99.544% / 99.609%. Owner macro P/R/F1: Microservices
99.066% / 99.453% / 99.258%; Javalin 100% / 99.351% / 99.660%;
Dropwizard 99.952% / 99.824% / 99.887%.

Archive-only scope is complete for 47 of 56 owners: all 14 Javalin and 33 Dropwizard
owners. One Dropwizard primary exceeds the unchanged single-directory guard;
eight Microservices owners contain packaging-added nested archives without a
controlled CDX hash. Global image-component completeness remains unproven in all
56 owners because opaque non-archive shading is a separate unresolved scope.
These are therefore conservative lower-bound precision and **known-delivered-only
recall**, not a universal full-image recall claim.

The historical R108 four-repository native/CDX-agreeing view (26 scored / 31 UNKNOWN)
is unchanged and retained alongside this report. Older packaged evaluations v1/v2
retain all 14 conservative Javalin root FP and their weaker module macros.
No old scope/score was overwritten. Owner instances are not independent projects;
the disclosed corpus is not fresh blind acceptance.

Thirty targeted evaluator tests passed, including exact-root/nested distinctions,
incomplete or wrong-image proof rejection, unverified nested CRC, empty references,
wrong versions, partial truth and preservation of conservative extras. Inputs,
all four prediction freezes/schemas and no-oracle provenance are preflighted before
the new labels are opened. Exact executed source and input hashes are retained.

```powershell
.\.venv\Scripts\python.exe benchmarks/evaluate_reactor_packaged_r109.py --output benchmarks/results/reactor-packaged-evaluation-r109-reproduce
.\.venv\Scripts\python.exe -m pytest tests/test_reactor_packaged_evaluation.py -q
```

Use a new output namespace. GAV comparisons do not attest classifier/type
qualifiers, directness, execution, original CI graph or publisher authenticity.

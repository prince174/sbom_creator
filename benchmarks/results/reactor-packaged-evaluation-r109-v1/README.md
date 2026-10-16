# R109 post-only packaged scoring, label v2 / frozen prediction R108

This report reuses the four already completed R108 service predictions. No scanner,
physical predictor, publisher, runtime policy or deployed service was changed.
The evaluator validates all prediction freezes and SBOM schemas before opening the
new independently constructed packaged labels. Its executed source is preserved.

| Reactor | Owners | TP / conservative FP / FN | P | Known-delivered recall |
|---|---:|---:|---:|---:|
| Microservices | 8 | 1341 / 12 / 8 | 99.113% | 99.407% |
| Javalin | 14 | 184 / 14 / 1 | 92.929% | 99.459% |
| Dropwizard | 34 | 2140 / 2 / 5 | 99.907% | 99.767% |
| Micro aggregate | 56 | 3665 / 28 / 14 | 99.242% | 99.619% |

Every final Maven GAV under the controlled owner prefix is retained. There is no
prediction filtering by expected GAV, reference SHA or matched archive path.
Own-root exclusion requires an independently attested effective-output SHA256,
matching owner GAV and an exact, non-nested physical and virtual archive path.
Packaging extras and unresolved identities are conservatively charged FP.

These are partial-reference metrics: precision is a conservative lower bound;
recall covers the known delivered GAV set and does **not** establish global image
recall. Full component completeness is unproven in all 56 owners because opaque
shading/primary/nested gaps remain. Archive-only completeness is established for
33 Dropwizard owners, a separate scope. The historical R108 26 scored / 31 UNKNOWN
scope view is unchanged and retained alongside this report.

Javalin's 14 extra GAVs are its unattested own primary candidates, deliberately not
silently excluded. Its owner macro precision is therefore **82.806%**, recall
99.351%, F1 89.877%; nine small owners have conservative precision at or below 90%.
Microservices has eight packaging-UNKNOWN jarmode-tools extras and four Hibernate
namespace errors. Missing known dependencies include ambiguous Netty observations,
Hibernate identities, Jdbi, Woodstox and Handlebars. Complete raw rows are in
`evaluation.json`.

The component comparison uses GAV and does not independently validate PURL type or
classifier qualifiers, directness, execution or publisher authenticity. These are
disclosed development cases, not fresh blind acceptance.

Verification: 17 targeted evaluator tests passed. An initial invocation using the
uninstalled global Python failed during import before reference access; rerunning
with `.venv/Scripts/python.exe` completed successfully. This was an evaluator
environment issue, not a service prediction failure.

Reproduce this immutable label-v2 attempt into a *new* output namespace with:

```powershell
.\.venv\Scripts\python.exe benchmarks/evaluate_reactor_packaged_r109.py --labels benchmarks/results/reactor-packaged-nested-r109-v2 --output benchmarks/results/reactor-packaged-evaluation-r109-reproduce
```

The current helper default may point to a later label-only attempt; each output's
`input-manifest.json` and exact executed evaluator snapshot identify its inputs.

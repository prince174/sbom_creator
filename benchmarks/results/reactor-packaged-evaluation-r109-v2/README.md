# R109 current packaged view: label v3, unchanged R108 predictions

The three reactor images have **56 shipped owner rows**, all with nonempty known
delivered GAV truth established independently from complete physical SHA256 bytes.
All final Maven GAVs under each owner prefix are scored; no prediction is removed
because it lacks a matching expected name, reference hash or reference path.

| Reactor | TP / conservative FP / FN | P | Known-delivered recall | F1 |
|---|---:|---:|---:|---:|
| Microservices, 8 owners | 1341 / 12 / 8 | 99.113% | 99.407% | 99.260% |
| Javalin, 14 owners | 184 / 14 / 1 | 92.929% | 99.459% | 96.084% |
| Dropwizard, 34 owners | 2140 / 2 / 5 | 99.907% | 99.767% | 99.837% |
| Micro aggregate | 3665 / 28 / 14 | 99.242% | 99.619% | 99.430% |

Exact-version coverage against these known delivered GAVs equals recall.
Conditional version accuracy for matched identities is 100%; wrong Hibernate
namespaces still produce FP and FN. The repository macro P/R/F1 is
97.316% / 99.544% / 98.393%. Counts are owner/GAV instances, not 56 independent
projects. There is no claim of a fresh scan, fresh Java prediction, blind
acceptance or runtime improvement in this post-only report.

Scope remains partial. Complete global image-component scope is unproven for all
56 owners because non-archive shading is not independently identified. The
separate complete standalone+nested archive scope covers 33 Dropwizard owners.
Javalin retains 14 unattested primary roots; Dropwizard retains one primary whose
directory exceeds the unchanged 2-MiB single-directory guard. Microservices has
eight packaging-added jarmode-tools nested archives without a controlled CDX hash;
they remain UNKNOWN and their predictions conservatively count as FP.

The Javalin primary candidates are **not** silently excluded. Its conservative
owner macro precision is 82.806%, recall 99.351%, F1 89.877%; nine small owners have
precision at or below 90%. Other remaining misses include ambiguous Netty, Jdbi,
Woodstox, Handlebars and Hibernate identities. Exact rows and missing/extra GAVs
are preserved in `evaluation.json`.

The immutable historical R108 native/CDX-agreeing view (26 scored / 31 UNKNOWN
across four Java repositories including Boot) is retained alongside this new
three-reactor view. These new partial-reference scores do not overwrite or close
its UNKNOWN scopes. Precision is a conservative lower bound and recall concerns
known delivered GAVs only; global image recall remains UNKNOWN.

Label v3 differs from retained v2 by accepting an unusual Unix mode only for a
safe, zero-byte ZIP directory. It does not accept symlinks or extract paths, and it
does not change a classifier or runtime resource budget. Independently labelled
GAV sets and every reported component score are identical between evaluation v1
and current v2. Child-enumeration UNKNOWN rows fall from 81 to eight in
Microservices, all eight remaining rows being packaging-added jarmode-tools.

The evaluator preflights all four R108 prediction freezes, completed outputs,
schemas and image-only provenance before opening the new labels. Each label
report is rechecked against its separate output hash manifest and image config.
The exact evaluator source and all relevant input hashes are preserved here.
Seventeen targeted tests passed; no new service process was started.

```powershell
.\.venv\Scripts\python.exe benchmarks/evaluate_reactor_packaged_r109.py --output benchmarks/results/reactor-packaged-evaluation-r109-reproduce
.\.venv\Scripts\python.exe -m pytest tests/test_reactor_packaged_evaluation.py -q
```

Use a new output namespace when reproducing. GAV scores do not attest classifier
qualifiers, execution, directness, the original CI graph or publisher authenticity.

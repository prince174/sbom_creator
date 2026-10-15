# R53: bounded context-gated Go replay

Date: 2026-10-15. Experimental regression, no production adoption.

Hypothesis: R52 eligibility checks preserve all existing supported Go fixtures
when passive helpers run with 30-second and 4 MiB stdout limits per invocation.
The input payload is limited to 32 MiB before helper invocation. Frozen R42
hashes and clean source checkouts are verified before prediction. Reference
hashes and native package graphs are read only after prediction.

All four cached fixtures remain eligible. Selected-main results are unchanged:
Hey development TP1/FP0/FN0; synthetic multimain TP1/FP0/FN0; fixed-control
httprobe TP0/FP0/FN0 with precision/recall null; fixed-control Lazygit
TP33/FP0/FN0 including exact versions. [Timings and results](go-context-replay-v1.json).
The largest replay takes approximately 11 seconds on this host, below its
30-second per-helper limit; these are observations, not a performance guarantee.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/replay_go_context.py
.venv/Scripts/ruff.exe check benchmarks/replay_go_context.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_g2_context.py benchmarks/test_go_g1_candidates.py benchmarks/test_go_g2_imports.py -q
```

All 27 unit cases pass. Initial Ruff B023 findings on a loop-local function were
fixed by binding invocation context explicitly; Ruff then passed.

Gate coverage is 4/4 on this known fixture set only, with development and control
partitions reported separately. This adds no independent control and establishes
no accuracy improvement. Native selected-main import labels still differ from
CycloneDX module-root declarations; the latter remain the primary reference for
their corresponding graph meaning. Runtime and all three SBOM outputs are
unchanged. Hostile helper inputs and whole-corpus coverage remain open checks.

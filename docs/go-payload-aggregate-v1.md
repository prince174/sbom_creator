# R47: aggregate Go payload budget

Date: 2026-10-15. Benchmark only; production runtime and frozen G2 rules unchanged.

Hypothesis: a metadata preflight can reject a set of individually admissible
binaries before their combined content exceeds a 32 MiB decoded payload budget.
The whole set must become UNKNOWN, rather than silently dropping later binaries.

The scratch fixture combines the previously paired Hey and Lazygit binaries.
Their sizes are 11,718,317 and 29,263,807 bytes. Each single-target plan passes;
the combined 40,982,124 bytes returns `UNKNOWN/aggregate_binary_budget`, with
no selected paths and no content scan started. Unknown dependency count stays
null: file sizes cannot establish that count.

The planner also rejects duplicate or excessive targets, unsupported literal
paths, ambiguous file inventory, nonregular files and invalid sizes. It estimates
base64 expansion and JSON overhead within the existing 64 MiB output cap.
The estimate is conservative planning, not proof of peak memory usage: metadata
has already been parsed and the actual scanner output cap remains necessary.

Validation: eight targeted pytest cases and Ruff passed, followed by the actual
two-binary image metadata scan. Exact boundary 32 MiB passes; 32 MiB + 1 byte
across two files rejects the whole set. [Machine-readable result](go-payload-aggregate-v1.json).

Reproduce from the existing paired binary caches:

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_payload_plan.py -q
.venv/Scripts/ruff.exe check benchmarks/go_payload_plan.py benchmarks/test_go_payload_plan.py benchmarks/check_go_payload_aggregate.py
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_payload_aggregate.py
```

Docker is used only by this external fixture harness. No application executable
is run. The report records the resulting image config digest.

This is a resource/coverage tradeoff, not a direct-dependency accuracy improvement.
Rejecting the combined image loses candidate coverage relative to two separate
reads, so the planner remains experimental and is not adopted into production.
No precision, recall or F1 is assigned. Next: verify registry acquisition identity,
authentication and digest pinning, then helper delivery and production guards.

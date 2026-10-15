# R52: experimental Go context eligibility gate

Date: 2026-10-15. No production or frozen G2 changes.

Hypothesis: unsupported build metadata must yield UNKNOWN before selected-main
traversal, including entry paths that merely share a module name prefix.

The experimental pure gate requires the exact supported toolchain and platform,
CGO disabled, Git revision matching the input commit, clean binary VCS metadata,
standard compiler/executable mode, and no known custom tags/instrumentation.
It rejects duplicate settings, ambiguous/replaced dependencies, workspaces,
owner mismatch and entries outside the module or containing traversal segments.
An eligible result explicitly leaves `direct_edge_proven=false`.

The existing Hey binary metadata is the positive input, read by the previously
built passive helper. Thirteen mutations exercise duplicate settings, dirty or
wrong revision, custom tags, CGO, platform/toolchain mismatch, wrong owner,
module-prefix collision, path traversal, replacement, duplicate dependency and
workspace. All yield UNKNOWN. Together with existing G1/G2 tests, 27 cases pass;
Ruff passes. No build reference or SBOM is an input to this gate.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_g2_context.py benchmarks/test_go_g1_candidates.py benchmarks/test_go_g2_imports.py -q
.venv/Scripts/ruff.exe check benchmarks/go_g2_context.py benchmarks/test_go_g2_context.py
```

This is not a complete production security boundary. Invocation time/output
budgets, malformed/hostile binary handling and broader positive fixture replay
remain necessary. Conservative rejection may reduce coverage and has not been
evaluated on the complete corpus. No precision/recall improvement is claimed.
Next: bounded helper invocation and unchanged positive-control replay before
considering integration; preserve separate module-root and selected-main labels.

# R62: fd lockfile/image version association

Date: 2026-10-15. Experimental association only; runtime unchanged.

Hypothesis: root manifest declarations plus a unique crates.io lockfile entry
and matching unique image crate version provide useful version candidates.
They cannot alone prove target/feature activation or direct build edges.

On the paired fd development fixture, 20 unique name/version candidates overlap
the 22 build-reference root edges, with no associations outside that graph.
Two reference edges have no association under this conservative rule. All source
records remain in the report, including UNKNOWN; no dependency is silently
removed. [Full results and missing edges](fd-versions-v1.json).

The candidate gate rejects multiple lock identities, absent/multiple image
versions, non-default registry sources and inherited workspace declarations.
It does not implement Cargo version-requirement solving or validate every Cargo
source override. Therefore even a unique association explicitly has
`direct_edge_proven=false`; build activation remains UNKNOWN. It is not safe
to convert these candidates directly into production direct-dependency labels.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_fd_versions.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_fd_versions.py benchmarks/test_fd_declarations.py -q
.venv/Scripts/ruff.exe check benchmarks/audit_fd_versions.py benchmarks/test_fd_versions.py
```

Both tests and Ruff passed. The reference is opened after source/lock/image
association. Direct precision/recall remains null: overlap is not edge proof,
and missing build-only or ambiguous identities are not automatically errors.
Next: inspect the two missing identities and retain negative findings before
deciding whether this approach warrants independent control evaluation.

# R55: original Go corpus source prerequisites

Date: 2026-10-15. Coverage audit only; no accuracy scoring or runtime changes.

Hypothesis: before adopting the experimental gate, measure which prerequisites
the unchanged source parser and narrow declaration reader can satisfy across
all ten original Go projects. Verify exact manifest commits and clean checkouts;
keep the existing development/control split and do not tune on these results.

All ten source trees parsed under the frozen linux/amd64 imports-only reader
with 30-second/4 MiB per-invocation budgets. The narrow go.mod declaration reader
supports seven projects. Assetfinder has no readable root go.mod; yq and upterm
use unsupported go.mod syntax. These three remain UNKNOWN rather than acquiring
guessed declarations. Lazygit, scc and upterm contain multiple main directories,
reinforcing the need for binary entry-point evidence.

[Per-project statuses and timings](go-corpus-context-v1.json). These counts mean
source parsing 10/10 and declaration prerequisites 7/10 only. No binary is
acquired by this audit; binary context is explicitly UNKNOWN for every row.
Previously paired experiments remain separate evidence and are not invalidated.
Neither count is direct dependency coverage, precision or recall. No new build
reference is produced, and no dependency edges are inferred from parsing success.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_go_corpus_context.py
.venv/Scripts/ruff.exe check benchmarks/audit_go_corpus_context.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_g1_candidates.py benchmarks/test_go_g2_imports.py benchmarks/test_go_g2_context.py -q
```

Ruff and 27 unit cases passed. Frozen rule hashes are checked before the audit.
Next: expand paired build/image references on the development subset, beginning
with waybackurls; do not relax the reader merely to inflate this prerequisite
count. Rust/Ruby paired coverage also remains outstanding.

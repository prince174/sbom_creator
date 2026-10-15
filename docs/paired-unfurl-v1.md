# R57: positive unfurl development pair

Date: 2026-10-15. Corpus expansion, no production adoption.

Built original manifest commit `8f10d050f1b0be12e505053da174f3f39e8eed74`
with pinned Go1.24/linuxamd64/CGO0 and CycloneDX gomod1.12 during the real build.
The shared harness verified clean source, identical builder/runtime application
trees, image binding and three SBOM schemas. Immutable reference files and hashes
are retained in [the receipt](../benchmarks/references/paired-unfurl-v1/receipt.json).

The passive G2 pass predicts DomainParser at its exact version. The native
selected-main imports and CycloneDX root graph agree on this one edge: TP1/FP0/FN0.
The manifest also declares tldomains, absent from the build root graph. Its
declaration is recorded separately; absence from this build is not erased or
automatically classified as a scanner error. Runtime inventory has three
components, with two source-only records remaining UNKNOWN in the baseline.
[Evaluation result](paired-unfurl-v1.json).

Initial fixture generation exposed a loop-variable naming bug: the application
binary was named `/application/generator-provenance.json`. It is the actual Go
application, not JSON; buildinfo confirms the source commit and module. Both
build and runtime use identical bytes. The completed receipt is preserved and
the verifier selects the sole regular application file. The generic recipe
generator is corrected for future builds; this fixture is not silently rebuilt.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/paired_unfurl.py
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_unfurl.py
```

Creation refuses an existing receipt. Passive verifier, prior waybackurls verifier,
Ruff and 17 context/traversal tests passed. This is known development data,
not a new holdout improvement; classifier rules and runtime remain unchanged.
Next: Rust/Ruby paired corpus expansion, preserving this declaration/build-graph
discrepancy as a scope case rather than tuning it away.

# R59: Rust fd paired-build checkpoint

Date: 2026-10-15. Build completed; pairing validation still pending.

Created a fresh exact-commit fd development checkout and built both builder and
runtime image stages. Rust1.85.1 and Debian runtime bases are pinned by digest
in the generated recipe. cargo-auditable0.6.6 and cargo-cyclonedx0.5.9 are fixed.
Build uses locked dependencies, debug profile, default features and explicit
`x86_64-unknown-linux-gnu`. The runtime copies those build outputs to `/app`.
No application executable is run; Docker remains an external benchmark tool.

Work checkpoint: `benchmarks/.work/paired-fd-v1`, with build/runtime image IDs,
recipe and logs. The retained reference includes both unfiltered and Linux-filtered
Cargo metadata, the build SBOM and actual compiler/generator version output.
The installed generator's saved help confirms that its omitted `--target`
defaults to the compiler host; rustc host is retained for the next validation.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/prepare_paired_fd.py
.venv/Scripts/ruff.exe check benchmarks/prepare_paired_fd.py
```

Both stages completed and Ruff passed. Resume reuses existing stage IDs and
refuses a changed recipe. This is not yet an immutable verified reference:
application-tree equality, image archive binding, schema checks, direct scope
labels and analyzer replay remain pending. No accuracy or coverage is reported.
Do not rebuild or duplicate this experiment next hour; continue from these IDs.

# R61: fd source declaration ownership and scopes

Date: 2026-10-15. Evaluation audit only; no runtime classifier.

Extracted root Cargo.toml declarations without reading the reference first:
26 records retain owner, alias/package name, normal/build/dev kind, target
expression, optional status and version requirement. Resolved version stays
null and build activation UNKNOWN. Workspace inheritance is retained rather
than resolved by this narrow audit.

After extraction, associated the 22 R60 reference root edges with declarations
by package name and exact kind/target expression. All 22 have one association;
four additional declarations remain outside this build root graph. This is
association coverage only, not classifier precision/recall. Reference versions
are evaluation fields and are not copied into source-derived predictions.
[Rows and associations](fd-declarations-v1.json).

[Official Cargo dependency documentation](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
distinguishes version requirements from resolved versions and describes different
dependency sources/platforms. The audit does not implement Cargo resolution,
target evaluation, workspace inheritance or optional-feature activation.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_fd_declarations.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_fd_declarations.py -q
.venv/Scripts/ruff.exe check benchmarks/audit_fd_declarations.py benchmarks/test_fd_declarations.py
```

The alias/scope/target/optional/inheritance preservation test passes, as does Ruff
after correcting its exception-type finding. Production and three SBOM outputs
are unchanged. Next: assess version/owner ambiguity from the source lockfile and
image on development data; retain unresolved activation and scope explicitly.

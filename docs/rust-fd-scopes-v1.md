# R58: Rust fd reference edge scopes before pairing

Date: 2026-10-15. Evaluation-only audit; no runtime changes.

Before building a new paired Rust reference, checked whether the existing fd
CycloneDX root graph could safely be called runtime dependencies. It cannot:
its 22 root edges map to 21 normal dependency-kind occurrences and one build
dependency occurrence in the retained Cargo metadata. Versions and ownership
are joined by exact opaque package IDs, without parsing names from identifiers.
The reference SBOM hash is checked against its existing provenance.

[Per-edge kinds and target expressions](rust-fd-scopes-v1.json) preserve build
activation as UNKNOWN. The retained `cargo metadata --locked --format-version 1`
command has no `--filter-platform`. [Official Cargo documentation](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)
states that the default resolved graph covers target platforms and distinguishes
normal, build and development dependency kinds. Thus neither a metadata edge nor
a target expression proves that a dependency was used by the Linux binary build.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_rust_fd_scopes.py
.venv/Scripts/ruff.exe check benchmarks/audit_rust_fd_scopes.py
```

All 22 root edges mapped, and Ruff passed. These are mapping counts, not direct
dependency precision/recall. The old image remains unpaired; this audit does not
upgrade it to a controlled source/image reference. No new build is claimed.
Next: create a fresh fd pair with explicit target/features/profile, retain both
filtered metadata and build artifacts, and label normal/build/dev separately.

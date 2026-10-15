# R63: explain the two missing fd version associations

Date: 2026-10-15. Negative finding; no rule or runtime change.

R62's missing cases have different causes. `nix` occurs at both 0.24.3 and
0.29.0 in Cargo.lock and the image. The root declaration requires 0.29.0, but
the experimental association rule has no Cargo requirement solver. Choosing
the newest or first image package would hide ambiguity and is not accepted.

`version_check` 0.9.5 is a root build dependency in the source and build
reference. It is present in Cargo.lock and absent from the final image crate
inventory. A build-time dependency need not survive in the shipped executable;
this absence is not automatically an SBOM error and cannot safely be repaired
by assigning runtime scope. Neither case becomes direct-edge proof from presence.

[Reproducible evidence](fd-unknowns-v1.json):

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/audit_fd_unknowns.py
.venv/Scripts/ruff.exe check benchmarks/audit_fd_unknowns.py
```

Both evidence assertions and Ruff passed. UNKNOWN records stay explicit, the
reference is not fed to a classifier, and precision/recall remains unmeasured.
The broader lesson for a future classifier is to distinguish declared direct
build edges from runtime presence and resolve package identities using actual
requirements. No acceptance based on this single development fixture.
Next: Ruby paired reference expansion; defer Rust requirement solving until a
tested, complete approach and independent control evaluation are available.

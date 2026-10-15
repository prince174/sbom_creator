# R60: verified Rust fd build/image reference

Date: 2026-10-15. Reference corpus expansion; no classifier improvement claimed.

Continued R59 from its existing stage IDs without rebuilding. Exact manifest
commit and clean source checkout verified. Exported builder `/out` and runtime
`/app` trees match paths, types, modes and file hashes. Saved runtime archive
index/platform/config identities match the analyzer's scanned configuration.
All three production CycloneDX 1.6 outputs validate. The actual build reference
uses CycloneDX 1.5 and validates with the existing benchmark reference validator.

An initial validation attempt incorrectly used the production 1.6-only validator
for the 1.5 reference. Corrected the harness to use its existing reference schema
validator; resumed the completed analysis rather than rerunning it or overwriting
its output. No production schema behavior changed.

[Immutable receipt](../benchmarks/references/paired-fd-v1/receipt.json) preserves
build recipe, Cargo manifests/lock, filtered and unfiltered metadata, tool version
and help output, application hashes, image binding and analyzer output hashes.
The analyzer receives source and image only; reference data is read afterward.

The build SBOM root has 22 edges: 21 normal kind occurrences and one build kind
occurrence, all mapped by exact IDs into Linux-filtered Cargo metadata. These
remain distinct from proof that code executed during compilation or at runtime.
[Recorded summary](paired-fd-v1.json) retains baseline UNKNOWN results. No direct
precision/recall/F1 is assigned, because a Rust direct classifier has not been
evaluated here. OS components remain in their separate output.

```powershell
# Refuses to overwrite the completed receipt:
.venv/Scripts/python.exe -X utf8 benchmarks/complete_paired_fd.py
.venv/Scripts/ruff.exe check benchmarks/complete_paired_fd.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_reference_pairing.py benchmarks/test_build_references.py -q
```

Tree, binding, four schema checks, Ruff and pairing/reference unit tests passed.
Production runtime and classifier rules are unchanged. Next: assess source-only
Rust declaration ownership/scopes against this development pair before making
any classifier proposal; expand Ruby paired references separately.

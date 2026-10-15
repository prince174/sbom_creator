# R56: paired waybackurls development reference

Date: 2026-10-15. Corpus expansion only; runtime unchanged.

The original manifest's waybackurls commit was built with the existing pinned
Go 1.24/Linux amd64/CGO0 recipe and CycloneDX gomod 1.12.0 during the same real
build. Source checkout is clean; binary build metadata confirms the exact Git
revision and unmodified state. The builder application tree equals the scratch
runtime tree; archive/config identities and all three output schemas are checked
by the shared pairing harness. No application executable is run.

Immutable [reference receipt](../benchmarks/references/paired-waybackurls-v1/receipt.json)
records tool provenance, hashes, image binding and analyzer output hashes.
The build SBOM remains evaluation-only. The analyzer receives source and image,
and the experimental candidate pass uses binary metadata and source imports.

Native package data, CycloneDX root edges and frozen G2 candidates all contain
zero external dependencies. Precision and recall remain null. The image's two
components (application and standard library) are inventory, not two direct
dependencies. [Evaluation result](paired-waybackurls-v1.json).

```powershell
# Creation refuses to overwrite an existing receipt:
.venv/Scripts/python.exe -X utf8 benchmarks/paired_waybackurls.py
# Repeatable verification:
.venv/Scripts/python.exe -X utf8 benchmarks/verify_paired_waybackurls.py
.venv/Scripts/ruff.exe check benchmarks/paired_waybackurls.py benchmarks/verify_paired_waybackurls.py
```

Build, pairing/schema checks, passive verification and Ruff passed. This is an
additional empty development reference, not evidence of improved accuracy or a
new control result. Next: paired unfurl development fixture with declared external
dependencies, then Rust/Ruby expansion. No classifier tuning on holdout data.

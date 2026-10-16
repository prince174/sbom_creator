# R110 current-default JavaScript publisher regression

All twelve cached R109 image-only no-lock predictions were published by the
actual service publisher with current R110 dataclass defaults:
`java_archive_components=true`, `java_nested_windows=false`. The non-Java rules
policy remains `image-evidence-and-payload-v4`.

Result: **36 valid final/os/full views have exactly the R109 coordinate
multisets; all twelve selected artifact ID sets are exact.** All original R109
payload observations, including Nest's explicit `declared_type_surface`, were
preserved verbatim. There were twelve real Syft conversion calls. Elapsed
publication/regression time was 80.797s.

This is a cached regression, not a new scanner run, physical measurement or
accuracy result. Image/source scanning, acquisition, Java image jobs and
checkout hooks were explicitly forbidden by the harness. No source repository,
project execution, reference labels, reference SBOM or build cache was used.
The cached input consists of R109 raw source/image catalogs, provenance and
previous published views; the old R108 payload facts were not used.

The 47 executed source/schema files and 98 input files were hashed before the
publications and verified afterwards. Live source still matched the executed
snapshot at completion. Exact executed runner and coordinate helper bytes are
retained beside the freeze. The current runner subsequently corrects only an
unused invalid-input guard's exception class from ValueError to TypeError for
lint consistency; the executed runner is not overwritten. All twelve actual
cached payload mappings were dictionaries, so this guard was never reached.

The conservative fixture extras remain present. Original R106 Chalk publication
failure remains separately pinned and is not declared repaired; all twelve
R109 baseline publications had already completed successfully. This regression
does not diagnose old Windows locking or the separate Linux OS-scanner delta.

# Registry acquisition: Crane config filename compatibility

The first complete local HTTPS API run exposed a Java corroboration failure that
archive-based accuracy runs did not exercise. Syft and Trivy succeeded, but the
physical reader rejected Crane0.22.1's root config member `sha256:<64 lowercase hex>`
because generic image paths forbid colons. The first API result is retained as
partial; it is not a successful Java accuracy result.

The outer Docker TAR index now permits exactly that root name. The sole permitted
digest-named entry must be the manifest's referenced regular config, at most4MiB,
and its complete SHA256 must equal the filename. The existing config-to-catalog
imageID binding remains mandatory. Normal image layers, ZIP paths and default TAR
indexing still reject colons. No aliases, links, duplicate paths, unused digest
entries or resource-budget increases are introduced. GNU/PAX effective names pass
the same exact-path guard before normalization.

Tests cover valid Crane and legacy names, wrong full hash/imageID, oversized config
rejection before body read, root aliases, ADS/traversal, links, duplicates and inner
layer isolation. This changes transport compatibility, not Maven identity rules,
reference labels or dependency scopes. A corrected installed API prediction is
required separately; passing unit tests alone does not establish component recall.

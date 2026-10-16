# R111 read-only public database validation review

Only the existing public Java DB snapshot and an immutable R110 copy of the
lookup implementation were read. No project names, build references, component
labels, scanner/publisher or source execution were used.

Snapshot: 1,553,915,904 bytes, SHA256
`c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25`.
Warm local timing: full SHA256 1.031 s; lookup constructor including another full
SHA256 1.047 s; post-query full-hash verification 1.234 s. The indexed zero-hash
miss completed below the host's timing resolution. These are host-local warm
measurements, not cold download or storage-latency acceptance.

`PRAGMA quick_check(1)` was explicitly capped at two seconds and two million VM
steps. It did not finish: SQLite was interrupted after 2.016 s. This is **not a
corruption finding**. Requiring a full quick/integrity check to finish inside that
cap would reject this legitimate frozen snapshot and could create a download
loop. Full database integrity is not asserted by bounded format/schema checks.

Actual supported structure:

- Public metadata `Version` is integer 1. The timestamp strings contain up to
  nine fractional digits and a timezone.
- SQLite `user_version` and `application_id` are both **0**; they must not be
  confused with public metadata Version 1.
- Page size 4096, page count 379374, freelist zero; page count × page size equals
  the complete physical file length. Encoding UTF-8, journal mode delete.
- Two tables and three indexes were observed. `artifacts.id` is INTEGER PRIMARY
  KEY. `indices_sha1_idx` is a complete, unique, non-partial SHA1 index.
- The fixed query plan performs `SEARCH i USING INDEX indices_sha1_idx` and
  `SEARCH a USING INTEGER PRIMARY KEY`, rather than scanning the artifact table.

Recommended supported-format validation is bounded read-only schema/index/PK
inspection and the fixed query plan, with the VM/time progress handler installed
before constructor metadata SQL. A complete file SHA256 binds the selected
snapshot; it does not establish publisher authentication or full SQLite
integrity. Genuine query corruption must remain a partial/UNKNOWN result.

The production R111 change separately adds constructor VM bounds, primary-key and
non-partial-index checks. Tests use real SQLite connections: handler-before-SQL
and reset, actual recursive VM interruption by instruction and time limits,
closed connection after failure, missing primary key and partial-index rejection.
The shared test fixture now explicitly closes SQLite handles; transaction context
managers alone do not close a connection and caused Windows atomic-rename test
failures. None of these findings change coordinate identity rules.

`report.json`, exact assessed source, exact diagnostic script and input hashes
preserve the measurement. Cooperative SQLite callbacks do not impose a hard
deadline on blocking filesystem I/O; process RSS and concurrency are not claimed.

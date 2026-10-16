# R109 post-analysis delivered archive and primary labels

No prediction, classifier audit or scanner inventory was an input. The helper
rechecked the immutable controlled-build references, actual build/runtime TAR
trees, and the OCI index/platform/config/DiffID-bound image bytes before labels.
All historical scoring views remain unchanged.

| Pair | Standalone SHA labels | Nested SHA labels | Primary owner attestations | Unknown nested/content rows | Known delivered owner/GAVs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Javalin | 185 | 0 | 14 | 0 | 185 |
| Dropwizard | 2145 | 0 | 34 | 1 | 2145 |
| Microservices | 1361 | 1259 | 8 | 8 | 1349 |

The first columns count physical file instances. The last column deduplicates
GAVs within each owner, including repeated standalone/nested copies. Qualified
PURLs remain in every identity row and conflicting qualified identities are not
resolved by merely observing an equal GAV count. All 1259 nested identities were
found in their own module's controlled CDX hash set; no global fallback was used.

Complete ZIP entry inventories record member paths, full SHA256, sizes and CRCs.
Each physical nested member is completely hashed and its parent ZIP CRC checked
before reuse by content hash. Zero-byte directory metadata with an unusual Unix
mode is allowed when its path is safe and it is not a symlink. No path is
extracted or followed. Symlinks, nonzero directories, unsafe paths, duplicate
names, encryption, truncated or corrupt bytes, and oversized/inflated content
retain strict rejection paths.

Javalin's new primary proof is independent of predictions and does not fill in a
missing historical `effective_output.sha256` field. It requires all of:

1. Concrete GAV/finalName/output directory from the receipt-hashed effective POM.
2. Matching native tree root and CycloneDX metadata owner.
3. A unique receipt-hashed literal Docker recipe command copying that exact
   target JAR into the owner prefix, followed only by the recognized dependency
   copy tail; the recorded runtime copies the controlled application tree.
4. No native/CDX dependency basename or SHA256 collision that could overwrite
   the primary during the following dependency copy.
5. The complete actual delivered primary SHA256 and exactly one canonical
   embedded pom.properties whose literal GAV matches the other owner evidence.
6. The actual image path, config and DiffID binding recorded beside the proof.

This proves a controlled primary owner, not publisher authenticity, directness,
execution, or absence of shaded dependencies. The source schema and negatives
are in `primary_scope_attestation_r109.py` and its focused tests.

Delivered archive scope is complete for Javalin's 14 owners and 33 Dropwizard
owners at the whole-JAR level. Dropwizard's example primary exceeds the existing
2 MiB single ZIP directory guard. All eight Microservices primaries contain one
packaging-added jarmode-tools archive lacking a controlled project CDX hash, so
these eight identities remain UNKNOWN. No packaging identity was guessed.

All primary JARs contain opaque non-nested classes/resources or an unparsed body.
Their entry hashes cannot identify or exclude shaded dependencies. Therefore
**full image component scope is not declared complete for any owner**. A separate
known delivered archive scoring view may use these labels and independently
attested primary exclusions while retaining this limitation.

Post-only resource policy: 8 GiB member reads, 128 MiB outer/32 MiB nested, 2 MiB
single ZIP directory, 128 MiB cumulative directories, two million parsed entries,
200x inflate, depth eight. These are evaluator limits; runtime policy did not
change. Actual complete-entry reads were about 2.92 MB Javalin, 134.54 MB
Dropwizard and 1.689 GB Microservices. Full tree/config verification is additional.

`verification.json` independently reproduces all 56 standalone owner label sets
from immutable CDX/tree inputs and verifies 386 complete archive inventories with
105496 hashed entry rows, source/dependency/output seals and coordinate unions.
It is a manifest check, not another physical scan or publisher authentication.

Earlier attempts are immutable: v1 stopped on Dropwizard's directory guard; v2
recorded unsupported child inventories as UNKNOWN; v3 corrected zero-byte
directory metadata without changing physical hash identities; v4 separately
adds the controlled primary-owner attestation above.

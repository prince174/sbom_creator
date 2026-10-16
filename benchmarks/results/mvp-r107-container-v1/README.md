# R107 installed Linux Microservices pipeline

The actual installed service pipeline completed successfully with the explicit
`SBOM_JAVA_NESTED_WINDOWS=true` opt-in. The stable service default was not changed.
This is a fresh Syft/Trivy scan plus physical verification and publication, not
replacement of the service result with a cached raw scanner inventory.

## Binding and isolation

`candidate-freeze.json` records all 44 source/data hashes, Docker build inputs,
the controlled image archive hash, public Java DB hash and harness hashes before
prediction. The source files exactly matched the parent's frozen `executed-source`
snapshot. Source/data and DB hashes remained unchanged during the run; all 44
installed files matched that snapshot.

The service image is `sbom-creator:mvp-r107`, image ID
`sha256:9030298f955b585040e1059c659e2767471555199fc4f66cb03aaa78780c0fd0`.
It built in 30.297 seconds. The analyzed image config was
`sha256:9363d3f231875f937c5a8904a1bb4d86e9d8ac0730eaf9d9f8d064e9cb848a8a`.

The container ran as UID 10001 with a read-only root filesystem, no network,
no capabilities, no Docker socket, no host credentials and no published port.
Only the controlled image archive and public scanner DB were read-only inputs;
no project repository or reference SBOM was mounted. Process scratch used the
default writable `/workspace`; `/tmp` remained 512 MiB. Memory/CPU limits were
3 GiB / 2 CPUs.

## Result and parity

The installed image-only pipeline took **523.962 seconds**; container setup and
execution took **527.344 seconds**, excluding the Docker build. The environment
uses Windows Docker Desktop bind mounts, so these times include that filesystem
I/O cost.

* `final.cdx.json`: 2,458 component instances.
* `os.cdx.json`: zero OS components in this artifact-fixture image.
* `full.cdx.json`: 2,458 component instances.
* Thirty-six grouped decisions remain UNKNOWN; the result remains partial.

All three CycloneDX schemas passed inside the installed pipeline. All three
coordinate multisets and all 2,458 selected artifact IDs exactly equal the
completed Windows R107 prediction. Schema file hashes and the exact output
hashes are retained in `windows-coordinate-comparison.json` and `verification.json`.
These checks are parity checks, not reference-based accuracy metrics.

`microservices/artifacts` preserves all 16 exports. Large catalogs are compressed
losslessly; `artifact-manifest.json` records original and stored hashes, all of
which were verified. Original local outputs remain in the ignored workspace.

## Resource accounting

The reader normalized 1,303,884,800 bytes once, consumed 94,360,364 payload read
bytes and 1,952,538,302 content-verification read bytes, and verified CRCs for
1,267 stored nested windows. It recorded 1,503 class witnesses, 56 resource
witnesses and 907 content-witness cache hits.

The directory ledger retained at most 256 fingerprints, with 362 charged
admissions, 106 evictions and 2,649 hits. Its cumulative charges were 9,813,237
directory bytes and 91,317 entries, below the unchanged 16 MiB / 100,000 limits.
There were no recorded budget guards or reader rejections. Independent parser
work remains visible as 926,914 parsed ZIP entries.

Eighty Docker cgroup samples reached an observed maximum of 730.9 MiB under the
3 GiB limit. This is not measured peak RSS, proof of a hard disk quota, or
acceptance under a 2 GiB limit. Full samples are in `resource-samples.json` and
their interpretation is in `resource-summary.json`.

No deployed service was changed, no Docker image was pushed, and no second scan
was run for this proof. Reference-based evaluation and any default-promotion
decision belong to the parent comparison stage.

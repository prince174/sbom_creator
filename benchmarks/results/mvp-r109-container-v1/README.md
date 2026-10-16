# R109 installed Linux npm type-surface check

The actual image-only pipeline passed once in the installed Linux RC. This was
an image scan/publication, not a replay, source build or reference evaluation.
Build time was 30.281s; the pipeline took 55.292s. The exact container time and
flags are in `nest/run.json`. All 47 installed source/schema hashes match the
parent Windows executed freeze. Source files and the mounted public Java DB
remained unchanged. Java modes stayed at their default false values; there are
no Java archive observations in this Node input. The shared harness mounted the
public DB read-only, but no Java component analysis required it.

The container ran as UID10001, read-only root, network none, no host ports,
no capabilities, no socket, no source/reference/credential mounts, 3GiB/2CPU,
512MiB `/tmp` and default writable `/workspace` scratch. No memory peak, RSS,
hard quota, concurrency or cold DB acceptance is inferred. Docker's observed
image ID is
`sha256:ad9e174893775b55c9c64742a8d243e8bf47125c51b2e592378370e895fdb61f`;
the full image inspection and executed harness bytes are retained. This is not
a deployment.

The original no-lock Nest image config was
`sha256:217d41d03eee667060258d2ce6751b97c728f4bab236f8cdb8a2b1ad3c920938`.
The installed prediction includes one `declared_type_surface` witness with the
same artifact ID, path, manifest SHA256 and payload facts as fresh Windows.
Execution, type validity and type file integrity are explicitly not established
by this final-filesystem presence observation.

All three SBOM schemas and all 13 lossless artifact exports passed. **Full
cross-platform parity did not pass:**

| View | Linux components | Windows components | Coordinate multiset parity |
|---|---:|---:|---|
| final, non-OS |308|308|Exact |
| os |88|89|Different |
| full |396|397|Different |

All 308 non-OS selected artifact IDs are also exact. The Windows OS/full views
contain an additional `systemd@252.39-1~deb12u2` coordinate from Syft's
`elf-binary-package-cataloger`; the Linux scan did not emit this observation.
OS artifact IDs differ more broadly because original scanner metadata differs.
The original OS/full inventories, ID deltas and coordinate delta are retained in
`parity.json`; the status is `PARTIAL_CROSS_PLATFORM_PARITY`. No OS observation
was deleted from an output to obtain equality. The underlying mechanism and OS
accuracy are not established by this feature check.

Two verification attempts are explicitly preserved. The first standalone
parity helper failed before comparison because it lacked the repository source
import path. The second strict helper then found the real OS/full discrepancy.
The final verifier reports all scope differences rather than relabelling strict
parity as passed. Neither verification issue caused an image scan or publisher
retry; there was only one installed pipeline invocation. No oracle was opened.

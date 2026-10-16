# R111: one public Java DB bootstrap and offline reuse

This installed service check used the existing immutable DBCP image only. It did
not read a reference, a source repository, expected component labels, or the old
public database. It is a cache/bootstrap and DBCP compatibility check, not a new
measurement of the complete Java corpus.

The single actual build completed in **35.797 seconds**. Docker image ID:
`sha256:4b31c639de2cb444b115dd5ced5bf1fbc9ce98cf3657b6fd2f0923a867f13698`.
All **48** installed source/data files match the pre-build snapshot. Dockerfile,
package configuration, source bytes and snapshots remained unchanged. The
executed Python program strings have LF hashes in the freeze; their exported
Windows text snapshots differ only by CRLF serialization, explicitly recorded
in `verification.json`.

`reconstructed-program-binding.json` additionally binds byte-exact portable LF
program files to those pre-execution hashes. They were recovered without
execution from AST literals in the exact frozen `executed-harness.py`. **This is
not independent capture of the container's executed argv:** the reduced saved
inspection receipts omit `Config.Cmd`/`Args`, and the stopped containers had
already been removed. Original CRLF snapshots were preserved, and no container
or network job was rerun to recover missing evidence.

Before any public download, a network-none container exercised nine native Linux
filesystem cases on the new named volume in **2.235 seconds**, with **zero
skips**: six symlink guards, no-replace publication against both empty and
nonempty directories, and positive synthetic SQLite publication/offline reuse.
The symlink ancestor case also proves that a missing cache child is not created
through a linked parent. These tiny synthetic databases remain under the
separate `/workspace/preflight` directory and are never the public cache.

| Actual installed run | Cold | Offline warm |
|---|---:|---:|
| Pipeline seconds | 110.125 | 9.171 |
| Java DB download command seconds | 100.4886 | 0 |
| Validation/publication seconds | 2.2127 | 2.0171 |
| Cache result | `published` | `reused` |
| final / os / full component counts | 4 / 0 / 4 | 4 / 0 / 4 |

The cold network job ran exactly once. The warm container had `--network=none`;
it reused the same new database and metadata without downloading or refreshing.
All three coordinate multisets are equal. All **six CycloneDX documents** passed
schema validation; **32 lossless exports** passed independent compressed/raw
hash verification. No vulnerability database was created. The small
`fanal/fanal.db` is the Trivy scan cache, separate from a vulnerability database.

The newly downloaded database is **1,554,915,328 bytes**, SHA256
`491fe2ddb9cfd09bfb1e216d49541e9b64628621ce3538c23ecee5864bfefd59`.
Its metadata SHA256 is
`40b61a18939abfcdbedb76959f5c548100ad245f0a04ca4949b67d90a9078bb2`:

```json
{
  "Version": 1,
  "UpdatedAt": "2026-10-16T01:00:20.589203513Z",
  "NextUpdate": "2026-10-19T01:00:20.589203Z",
  "DownloadedAt": "2026-10-16T07:11:22.521364172Z"
}
```

**These are different bytes from the previous frozen database.** This check does
not establish unchanged accuracy for all Java projects with the new database.
The old cache was not mounted or modified by this harness. The new volume
`sbom-r111-public-java-1792134539387152100` and public DB are retained locally for
reproduction; the 1.55 GB database is not copied into Git evidence.

Both actual pipeline containers ran as UID 10001, read-only, without capabilities
or privilege escalation, with 3 GiB / 2 CPU limits. Their only mounts were the
read-only immutable input archive and the new writable workspace volume. No
source, reference, Docker socket, service credentials or host proxy environment
was passed. The default Java archive-components setting was true; both Java
reader environment overrides were absent. This does not certify hard disk
quotas, process peak RSS, adversarial shared-workspace writers or general
concurrency capacity.

Trivy 0.75.0 uses the public repository defaults
`mirror.gcr.io/aquasec/trivy-java-db:1` and
`ghcr.io/aquasecurity/trivy-java-db:1`. These tags are mutable, and the selected
transport endpoint was not separately retained by the runtime. The actual
downloaded bytes and metadata are recorded above. Supported SQLite
schema/index validation and full SHA256 do not prove publisher authenticity or
global GAV uniqueness. Official source: [database flags](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/flag/db_flags.go),
[public repository defaults](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/javadb/client.go),
and [download-only early return before scanning](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/commands/artifact/run.go).

The preceding `mvp-r111-cold-cache-v1` contains a preserved host CLI parser
failure: excluding Windows plugin-discovery variables hid buildx and caused
`--progress` to be rejected before any build or public download. Read-only CLI
probes confirmed the cause. Version 2 adds only nonsecret Windows OS discovery
variables to the host Docker CLI environment; none is forwarded into the job.
The v1 attempt is not a second download or a failed network measurement.

Commands actually used:

```powershell
.venv\Scripts\python.exe benchmarks/check_mvp_r111_cold_cache.py --build --output benchmarks/results/mvp-r111-cold-cache-v2
.venv\Scripts\python.exe benchmarks/verify_mvp_r111_cold_cache.py
```

Never rerun these commands into an existing namespace. A failed cold public
network job must be preserved and must not be retried automatically.

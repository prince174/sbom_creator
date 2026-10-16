# R110 installed default-config Java REST verification

One build and one actual installed pipeline ran against the existing immutable REST
image archive. No reference SBOM, project source, build cache or service credentials
were mounted. No deployed service or reference image was changed.

- Installed image: `sbom-creator:mvp-r110`, config
  `sha256:e7ad622093c917aecc4d8c7e3094286e54c485c91566a5462b6d7c95d9be423f`.
- Build 32.078 s; pipeline 120.445 s; container 122.469 s. Timings exclude registry
  acquisition of the already supplied image archive and cold Java DB download.
- Non-root 10001, read-only root filesystem, network none, no Docker socket,
  capabilities dropped, no new privileges; 3 GiB / 2 CPUs / 128 PIDs, 512-MiB `/tmp`.
  Public Java DB and input archive were mounted read-only; workspace was writable.
- All **47 source/schema hashes** exactly match the frozen Windows candidate;
  source and public DB stayed unchanged. All 16 exported artifacts verified.
- Both `SBOM_JAVA_ARCHIVE_COMPONENTS` and `SBOM_JAVA_NESTED_WINDOWS` were **absent**
  from the container environment and Docker image ENV. Actual Settings selected
  archive components **true**, nested flag **false**, policy
  `image-delivered-archive-v7`. There was no feature-flag override.

Fresh Syft/Trivy scans, physical reads and real publication completed. The final,
OS and full coordinate multisets equal the completed Windows R110 REST prediction:
**109 / 143 / 252** components. These are whole-view counts, not project TP counts.
All 109 selected non-OS artifact IDs and observed payload facts match. Complete
metadata-only archive proof sets are both empty for this input; v7 selection is
independently verified and no archive proof was fabricated to make a test pass.

The overall result is **PARTIAL_CROSS_PLATFORM_PARITY**: the 143 OS artifact IDs
differ on each platform despite exact OS coordinate equality. Raw scanner outputs
also differ: Linux has 253 observations / one UNKNOWN group, Windows 258 / six.
The five Windows-only observations have `binary-classifier-cataloger` provenance
and remain unselected; both raw inputs, counts, locations and deltas are preserved
in `raw-observation-audit.json`. The producer/root cause is UNKNOWN. There was no
scan retry, OS filtering or suppression to force parity.

An initial local harness preflight rejected the parent freeze's 69 entries before
creating a build/output: 47 source/data files plus 22 Python bytecode-cache files.
The adapter now selects only the 47 actual package files. The immutable parent
freeze was preserved, and no prediction was rerun for this bookkeeping issue.
The exact executed driver/shared harness and parity verifier are retained.

The historical smoke without `--reader-defaults` now explicitly requests its old
false/false selection (or its explicit true options); R110 alone uses the new
default-config smoke. Ten focused tests cover omitted overrides, legacy selection,
conflicting options and bytecode/source freeze separation; Ruff passed.

Accuracy is assessed separately after analysis; this harness never reads labels.
No process RSS, hard filesystem quota, safe parallelism, cold DB download,
publisher authenticity, execution or complete original-CI graph is claimed.

```powershell
.\.venv\Scripts\python.exe benchmarks/check_mvp_r110_container.py
.\.venv\Scripts\python.exe benchmarks/verify_mvp_r110_container.py
.\.venv\Scripts\python.exe benchmarks/audit_mvp_r110_raw_observations.py
```

Completed namespaces are immutable; reproduce into a new output path. This run is
complete and all owned Docker processes/containers have exited.

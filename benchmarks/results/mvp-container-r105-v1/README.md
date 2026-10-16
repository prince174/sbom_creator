# R105 container checks

These checks exercise the installed service package, rather than importing the
working source tree. No deployed service was changed, and no image was pushed.

* `stagecheck` validates all pinned Docker stages and the `/ko-app/crane` copy
  path. Its source changed during build, so it is not the accepted RC snapshot.
* `stagecheck-smoke` and `stagecheck-helper-debug` retain the failed preliminary
  run: the old validator rejected Trivy's CycloneDX 1.7 peer output. The pipeline
  correctly reported Java `UNKNOWN` rather than claiming a complete result.
* `final-build` records the frozen source/data hash snapshot and the successful
  `sbom-creator:mvp-r105` build. No source/data file changed during that build.
* `final-smoke` runs the actual image-only pipeline as UID 10001, with a read-only
  root filesystem, no network, no capabilities, and limits of 3 GiB / 2 CPUs.
  Only the controlled Boot image archive and public scanner Java DB are mounted
  read-only; there is no source repository, reference SBOM, Docker socket, host
  credential, or published port. The full pipeline took 82.589 seconds. All three
  SBOM schemas passed, and all 42 installed source/data hashes match the snapshot.
  The final output has 95 non-OS components, 143 OS components and one UNKNOWN;
  these counts alone do not establish accuracy. Post-analysis evaluation is
  separate from this smoke check.
* `http-smoke` starts the installed HTTP entry point inside an isolated container
  and checks health, authentication, image-only request parsing, and rejection of
  an incomplete repository/commit pair. It queues no analysis and exposes no
  host port. Actual image analysis is covered by the preceding pipeline check.
* `cache-config-build` adds the writable default cache location
  `SBOM_TRIVY_CACHE_DIR=/workspace/trivy-cache`, producing the separate tag
  `sbom-creator:mvp-r105-cache-config`. `cache-config-smoke` confirms default
  settings, writable workspace/cache paths, a read-only HOME and read-only Java
  DB, with installed package hashes identical to the successful pipeline RC.
  A cold network database download was not exercised.
* `final-fallback-build` incorporates the final scanner safety correction:
  optional peer schema `ValidationError` now follows the existing explicit
  UNKNOWN fallback. `scanner.py` is the only changed source/data file relative
  to the cache-config RC. `final-fallback-smoke` repeats the entire installed
  Boot pipeline using the actual default cache configuration in 73.262 seconds
  (75.062 seconds including container setup). The three component coordinate
  multisets and all selected artifact IDs equal the preceding successful RC;
  all 42 installed file hashes match the new build snapshot. Export hashes and
  installed Python dependency versions also match. These checks are recorded in
  `final-fallback-verification.json`.

The older `sbom-creator:r104-direct` and both R105 image tags remain available.
The final release-candidate tag is `sbom-creator:mvp-r105-final`, image ID
`sha256:318289b205c2bd0597dfbb1cf6a20169f39cefe598758f5ca91d261cd7850a8d`.
The earlier cache-config image ID is
`sha256:b38272bcd1e34f9972e770f5ed50c2d2eb623abe2b6d5e94a3b7c7dd2cf8bb57`.

`final-fallback-smoke/artifacts`, `final-smoke/artifacts` and
`stagecheck-smoke/artifacts` retain exported outputs
outside the ignored workspace directory. Large JSON catalogs are compressed
losslessly with gzip; `artifact-manifest.json` records both original and stored
hashes. Local original outputs and the scanner cache remain in `workspace`.

The official crane image reports commit
`8a72a424fdecb4caa14f2d525e5d2503331442b5` for its version; the official repository
tag `refs/tags/v0.22.1` resolves to that exact commit. The earlier attempted
Windows invocation of a Linux extensionless binary was an operator error and
caused the Windows association chooser; details are in `host-probe-incident.json`.
All subsequent Linux binary probes ran inside containers.

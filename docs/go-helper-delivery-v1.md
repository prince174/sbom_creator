# R51: passive Go helpers in a compiler-free Linux fixture

Date: 2026-10-15. Packaging feasibility only; no production integration.

Hypothesis: the frozen source-index and binary-buildinfo readers can be shipped
as precompiled static Linux executables, without requiring Go, Docker or project
build execution in the scanning service.

All six R42 frozen source hashes are checked before building. The two trusted
helpers are compiled using the pinned Go 1.24 builder with CGO disabled, local
toolchain, proxy off and build network disabled. Each is built from two different
source paths with `-trimpath -buildvcs=false`; byte comparisons pass. These are
two builds in one builder environment, not independent toolchain reproducibility.

The final scratch fixture contains only compiled helper outputs and runs as
65532:65532. Both readers ran with read-only root filesystem and input mounts,
no network, all capabilities dropped, no-new-privileges, 256 MiB memory and
32-process limits. They parsed the existing Hey source and binary without
executing the target application. Both JSON results exactly matched the frozen
Windows helper outputs for the same inputs and target linux/amd64.

[Report](go-helper-delivery-v1.json) records builder/fixture identities, frozen
source hashes and parser version. Ruff and all 13 existing G1/G2 unit tests pass.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_helper_delivery.py
.venv/Scripts/ruff.exe check benchmarks/check_go_helper_delivery.py
.venv/Scripts/python.exe -X utf8 -m pytest benchmarks/test_go_g1_candidates.py benchmarks/test_go_g2_imports.py -q
```

Docker remains an external benchmark/build tool. The scratch fixture is not a
new required service input and is not deployed. Production Dockerfile, runtime
dependencies, classifier rules and three SBOM outputs are unchanged.

The [official Go build documentation](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies)
describes the trimpath and VCS-stamping controls; the experiment pins its actual
builder rather than relying on the current documentation version.

Limits: one positive source/binary, linux/amd64 only, unchanged parser limits.
No general parser safety proof or direct-dependency accuracy gain is claimed.
Next: define bounded helper invocation and unsupported-build guards before any
production adoption. Module-root direct declarations and selected-main imports
must retain separate meanings and control metrics.

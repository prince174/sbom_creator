# R49: registry payload and mutable tag race

Date: 2026-10-15. External acquisition experiment, no production change.

Hypothesis: direct Syft registry acquisition can retrieve the same bounded Go
payload, reject a tag that changed between scans, and retain the original bytes
when the second request uses the resolved immutable manifest digest.

The harness starts its own registry 2.8.3 container using the recorded local
image ID, bound only to an ephemeral loopback port. It pushes the existing Hey
fixture, scans via explicit `registry:`, replaces the same tag with the existing
clean multimain fixture, and scans again. No application executable is run.
Docker is used only outside the scanner, to construct and remove this fixture.

All checks passed:

- Both registry content scans returned readable payloads with different hashes
  and different image configuration digests.
- A rescan of the changed tag with the original expected configuration digest
  raised `Rescanned image differs` before returning payload.
- The original immutable manifest reference still resolved to the original
  configuration and payload after the tag moved.
- The owned registry container was removed in `finally`; no service was changed.

[Recorded digests and result](go-registry-identity-v1.json). Reproduce using the
existing paired fixture images and local registry image:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_registry_identity.py
.venv/Scripts/ruff.exe check benchmarks/check_go_registry_identity.py
.venv/Scripts/python.exe -X utf8 -m pytest tests/test_scanner.py benchmarks/test_go_payload_plan.py -q
```

The 24 targeted unit cases passed alongside the real registry experiment.
This fixture deliberately uses unauthenticated loopback HTTP. It does not prove
TLS, authentication, credential isolation, multi-platform index behavior or
registry garbage collection resilience. HTTP settings exist only in the temporary
experimental configuration and are not added to runtime defaults. No direct
dependency precision/recall is claimed and the frozen G2 classifier is unchanged.

The pinned Syft 1.51.1 [registry configuration source](https://github.com/anchore/syft/blob/v1.51.1/cmd/syft/internal/options/registry.go)
defines the HTTP and authentication options used to plan this experiment.
Next stage: authenticated TLS fixture and credential isolation, then helper
delivery and production guards before considering G2 integration.

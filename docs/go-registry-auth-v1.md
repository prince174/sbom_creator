# R50: authenticated TLS Go payload acquisition

Date: 2026-10-15. External benchmark only; production and frozen G2 unchanged.

Hypothesis: the registry payload bridge can read through TLS and scoped basic
authentication while rejecting missing credentials, wrong password, credentials
for another authority and an untrusted certificate.

A fresh registry 2.8.3 container listens only on an ephemeral loopback port.
The harness generates a one-day self-signed localhost certificate and random
fixture password. A previously installed service image is used solely as an
offline password-hash helper; its immutable local ID is recorded. No service
is deployed or modified. Docker creates the external fixture; Syft reads directly
from `registry:` with an isolated temporary Docker configuration and explicit CA.
No host CA or credential configuration is changed.

The authenticated read passed and returned the Hey payload. All four negative
cases failed without returning payload. Negative checks assert scan failure,
not a particular HTTP/TLS diagnostic. [Recorded results](go-registry-auth-v1.json)
contain no generated credentials, password hashes, private keys or raw scan output.
The owned container is removed in `finally`; temporary secret material is removed
when the temporary directory closes.

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_registry_auth.py
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_registry_identity.py
.venv/Scripts/ruff.exe check benchmarks/check_go_registry_auth.py benchmarks/check_go_registry_identity.py
.venv/Scripts/python.exe -X utf8 -m pytest tests/test_scanner.py benchmarks/test_go_payload_plan.py -q
```

The original HTTP tag-race experiment is rerun because its shared scan helper
now accepts optional CA and credential settings. Runtime settings are unchanged.
The pinned [Syft registry option source](https://github.com/anchore/syft/blob/v1.51.1/cmd/syft/internal/options/registry.go)
documents authority-scoped credentials and explicit CA handling.

Limits: self-signed loopback/basic-auth fixture only; no bearer-token flow,
enterprise proxy, multi-platform index or general credential-isolation proof.
Direct-dependency accuracy remains null: this verifies acquisition, not edge
classification. Next: helper packaging and fail-closed production guard design,
keeping module-root declarations separate from selected-main imports.

# Production and verification modes

Production remains the default: source repository, exact commit and image.
No reference is required or accepted in production mode. Analysis inputs and
dependency classifiers are unchanged.

Verification runs exactly that analysis first, then reads its published
final.cdx.json and direct-dependencies.json to create evaluation.json. The
reference cannot influence classification. Initial reference support is
CycloneDX1.6, at most8MiB serialized JSON, root-project runtime dependencies.
Scope defaults to unknown; explicit runtime scope is required for metrics.
Build/test scope, arbitrary module graphs and other schema versions remain
unsupported rather than guessed. The caller asserts build/commit identity;
this first stage does not cryptographically attest the reference's build.

CLI:

```powershell
python -m sbom_creator analyze --repository-url https://example.com/team/repo.git --commit <commit> --image registry.example/app@sha256:<digest> --output result --run-mode verification --reference-sbom sbom.json --reference-scope runtime
```

API `/v1/analyses` adds optional fields:

```json
{
  "repository_url": "https://example.com/team/repo.git",
  "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "image": "registry.example/app:1",
  "run_mode": "verification",
  "reference_scope": "runtime",
  "reference_sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
}
```

The reference above shows placement only; supply the complete valid build SBOM
including root identity and dependency graph. Verification artifacts include
evaluation.json; production artifact list remains unchanged. Wrong or absent
owner/profile/scope gives UNKNOWN, not empty-success precision100%. Measured
results include TP/FP/FN, precision/recall/F1, counts and UNKNOWN declarations.
Identity comparison uses purl ecosystem/namespace/name/version, ignoring scanner
qualifiers. Inventory-only scanner edges are never treated as confirmed direct
edges: evaluation uses the service's explicit DIRECT records.

Security limits apply after API JSON parsing; deployments must retain request
body limits at their HTTP boundary. No Docker runtime dependency, extra privileges
or deployed-service change is introduced. All three inventory outputs are intact.

This is the first stage of the user's Java/JavaScript completion request.
Current paired corpus remains6JavaScript/2Java; target10each is outstanding.
Next: real paired replay of this evaluator, module/scope/binding checks, then
expand references and evaluate ready-made engines before classifier integration.

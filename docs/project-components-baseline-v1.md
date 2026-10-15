# Component identity baseline for Java/JavaScript fixtures

2026-10-15. Component identity/version matching is measured separately from
direct edges. Predict from image Syft evidence first, then read reference.
Known fixture application paths `/app/` and `/application/` define the measured
project universe; whole-image final counts and excluded platform records remain
visible. This is a fixture-path projection, not a general production ownership
classifier. It is not installed in the runtime or used to hide inventory records.

[Rows and exact differences](project-components-baseline-v1.json).
Not all projects exceed90%. Java Commons Compress has seven predicted and seven
reference components, but only five exact identities match: Syft emits ASM under
org.objectweb.asm instead of org.ow2.asm, and XZ under org.tukaani.xz instead of
org.tukaani. No name-only alias substitution is applied without evidence.
This is why equal component counts are insufficient.

Some npm fixtures also retain extra app-local coordinates relative to the
production build reference; package location alone is not enough to normalize
scope. Empty reference projects retain null accuracy. The full inventory is
unchanged; no claim of >90% production accuracy follows from this baseline.

Run `python benchmarks/score_project_components.py`. Two tests verify equal-count
mismatches and empty metrics; Ruff passes. Next: complete all Java pairs, compare
ready-made identity/graph techniques on fixed scopes and explain differences
without oracle-informed corrections.

R81 update: all 20 pairs are now included. Recursive CycloneDX inventory traversal corrects the former JS reference count from 178 to 188. See [full comparison](java-js-twenty-comparison.md); the previous shallow-count interpretation is superseded.

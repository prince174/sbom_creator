# Chalk: eighth JavaScript pair

Controlled original-commit build with CycloneDX npm6.0.1, identical application
tree copied to runtime. Pairing harness validated tree hashes, image binding
and three output schemas. Reference is evaluation-only.

Chalk5.4.1 has no external production root dependencies in this build. Evaluator
returns TP0/FP0/FN0 and null precision/recall/F1/version accuracy; this is an
empty-set regression, not additional positive accuracy evidence. Bundled source
under vendor is not automatically a separately declared direct npm dependency.

[Result](paired-chalk-v1.json),
[receipt](../benchmarks/references/paired-chalk-v1/receipt.json).
Build: `python benchmarks/paired_express.py --project chalk`.

Eight JavaScript/two Java pairs complete. Next: ms and commander-js to reach ten
JavaScript pairs, then Java expansion. Workspaces/optional/peer/profile coverage
still requires explicit additional fixtures and is not proved by project count.

# Debug: seventh JavaScript pair

Controlled build of original manifest commit with CycloneDX npm6.0.1 during
production pruning, same application tree copied into runtime image. Existing
pairing harness validates tree hashes, image binding and three output schemas.
Reference remains evaluation-only. No target application is executed.

New evaluator result: direct ms2.1.3, TP1/FP0/FN0, version accuracy1, UNKNOWN0.
[Evaluation](paired-debug-v1.json),
[immutable receipt](../benchmarks/references/paired-debug-v1/receipt.json).
This is one additional positive pair, not general accuracy100%.

Build command: `python benchmarks/paired_express.py --project debug`.
Production classifier is unchanged. Seven JavaScript and two Java pairs are now
complete; remaining Java/JS projects are the only active corpus priority.

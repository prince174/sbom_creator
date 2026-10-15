# Java Commons Compress paired reference

Original manifest commit built using pinned Maven/JDK17 and CycloneDX Maven2.9.3.
Seven compile/runtime root edges agree between build SBOM, native dependency
tree and effective POM. Test/provided/system scope excluded by recorded recipe;
active profiles and tool version retained. Each dependency's execution remains
unknown. Reference is evaluation-only.

Library JARs and runtime dependency JARs are copied byte-for-byte from the build
stage into a scratch artifact image. This is a library artifact fixture, not a
deployed runnable application image. Tree hashes, archive/config binding and
three output schemas pass; receipt/reference hashes and root labels replayed.

[Receipt](../benchmarks/references/paired-commons-compress-v1/receipt.json).
Run `python benchmarks/paired_java.py --project java-commons-compress` to create
a fresh pair; completed receipt prevents overwrite. Three Java pairs complete.
The generic harness resumes existing stage IDs only with unchanged recipe.

No production classifier gain is claimed. Next: remaining seven Java projects,
component identity/version scoring as well as direct-edge scoring, and comparable
top-three techniques for Java/JavaScript. Other language work stays deferred.

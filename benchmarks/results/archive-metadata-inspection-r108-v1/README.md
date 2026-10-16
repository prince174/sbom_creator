# R108 bounded metadata-only archive inspection

This is physical inspection, not an accuracy run or a classifier change. Candidate selection used **all prior unconfirmed original Syft Java observations**, without expected package names or reference access. Syft and Trivy outputs are cached R107 producer outputs. Image-byte reads, nested ZIP validation, metadata reads and whole-JAR digests are fresh.

| Image | Selected observations | Classless archives inspected | UNKNOWN | Physical inspection seconds |
|---|---:|---:|---:|---:|
| Petclinic Microservices | 180 | 170 | 10 | 6.547 |
| Dropwizard | 259 | 31 | 228 | 3.719 |

The 201 inspected observations contain 31 distinct SHA256 contents. Every inspected classless JAR received a complete physical SHA256 and SHA1 pass. The extra digest passes read 979,340 bytes across both images, below the separate 32 MiB inspection ceiling and charged to each reader's existing 8 GiB verification ledger. For 37 nested stored observations, this pass independently matched the already verified complete stored-member SHA256 and CRC. Flat files have no declared whole-JAR CRC: computing a CRC does not authenticate their publisher.

All existing image-config, final-path/layer, nested-chain, ZIP/path/index/inflate, deadline and byte limits apply. Captured entry names plus manifest/properties contents are capped at 32 KiB per observation; the actual maximum was 932 bytes. The reader's class/resource witness counters remain zero. Original runtime payload facts are copied verbatim and were not changed. A zero class count is an archive inspection result, not proof of runtime use or directness.

UNKNOWN reasons remain visible: ten Micro observations and 227 Drop observations have conflicting access paths; one Drop archive exceeds the per-ZIP directory budget. Nothing relaxes those guards. Peak RSS and a hard filesystem quota were not measured by this helper.

## Actual structures

All 20 distinct **observed** Spring Boot starter PURLs have exactly these entries:

```text
META-INF/
META-INF/MANIFEST.MF
META-INF/LICENSE.txt
META-INF/NOTICE.txt
```

There is no Maven `pom.properties` in those archives. The actual manifest includes `Spring-Boot-Jar-Type: dependencies-starter`, `Implementation-Version: 4.0.1`, an automatic module name, and a descriptive implementation title. These fields do not establish a Maven group/artifact. Some original Syft starter namespaces are malformed; both original and peer observations remain in the digest index. No namespace is guessed from the filename or module name.

The separately observed Spring AI starter is also classless but contains canonical `META-INF/maven/org.springframework.ai/spring-ai-starter-model-openai/pom.properties`, with literal group/artifact/version values. The `listenablefuture` empty-conflict artifact contains manifest, POM and properties only. Conversely, classless `csstype` also contains actual `.d.ts` and `.flow` files: a classless archive need not be metadata-only. No resource policy was changed here.

## Reproduction and artifacts

`freeze.json` was written before physical inspection, including exact source/input hashes. The initial 44 source/data files still matched when `executed-source` was saved; later new modules are not part of this inspected implementation. `microservices.json` and `dropwizard.json` contain every observation, entry name, bounded raw metadata, complete digests and binding. `digest-index.json` groups identical actual content and retains all path/layer/config occurrences, original identities and peer PURLs for independent public-hash lookup. It contains no oracle-derived identity.

Run the physical inspection in a **new** namespace; the helper refuses to overwrite a result:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/inspect_archive_metadata_r108.py --output benchmarks/results/archive-metadata-inspection-r108-new-run
```

The completed report can be checked without repeating physical inspection:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_archive_metadata_inspection_r108.py
```

That check verifies frozen source snapshots, unchanged producer/provenance/image hashes, unchanged prior facts, capture/resource bounds and digest-index consistency. No new scanner, Docker build, runtime publication, reference or build cache was used.

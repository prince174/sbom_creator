# R113 two-case cached publication regression

The runtime publication-diagnostic change (`7726706`) was frozen as 49 actual
source/schema files before these two sequential jobs. No image scan, physical
reader, acquisition, source resolver, build or oracle was invoked. The only
external commands were two pinned Syft conversions, one per publication.

| Cached inputs | Prior comparison | Final / OS / Full | Seconds | Result |
| --- | --- | ---: | ---: | --- |
| Original R106 Chalk diagnostic catalogs/payload | Separate successful R106 Chalk diagnostic | 199 / 89 / 288 | 6.453 | PASS |
| R109 Nest image catalogs and declared-type payload | R109 Nest published SBOMs | 308 / 89 / 397 | 9.531 | PASS |

For both jobs all three component-coordinate multisets, selected-artifact IDs,
complete original payload mappings (including UNKNOWN facts), and original source
and image catalogs are unchanged. Nest retains its one declared-type witness.
All six published CycloneDX documents passed schema validation.

Overall elapsed time is 16.125 seconds; this excludes all analysis that generated
the cached inventories and payload facts. No new accuracy measurement is claimed.
Chalk's project root remains an empty/unsupported accuracy case; whole-image
component counts do not turn it into a successful precision/recall control.

The original R106 failed run and its `PermissionError` diagnostic remain unchanged
and are input-hashed. Historical operation/cause remains UNKNOWN; successful
publication does not establish a locking fix. The new diagnostics are verified
separately by the runtime's injected-failure tests.

The final report was written only after both jobs and rechecking 49 source/schema
files, 16 original input files and the converter binary. It seals both case run
files, which seal all their published analysis outputs.

- Freeze SHA256: `45fc4dc22296366010173537987dbc88880f6bf2f0fdf613d26794465abd21f7`
- Report SHA256: `d72f8041f23408745e86df26367f92fe784ecac4b602ab3d27674f2db3a366a3`

Twenty synthetic runner-contract tests and Ruff passed before execution. This
README was added afterward and changes no executed source, freeze or sealed result.

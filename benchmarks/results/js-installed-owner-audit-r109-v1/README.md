# R109: JavaScript installed-owner and delivered-file diagnostic

This is a read-only, post-analysis diagnosis of four exposed controls. No
classifier, production setting, image, scanner result, publisher result or
reference was changed. It is not a new prediction or independent acceptance.
Historical accuracy reports were consulted to select these already exposed
weak cases before inspection. Oracle-access flags below refer specifically to
new direct `references/*/sbom.json` reads, not ignorance of those old outcomes.
The complete actual image archives and R106 raw inventories were SHA256 checked;
R108 final/os/full and selected inventories were frozen as inputs. The executed
diagnostic and source hashes are in `freeze.json`. Physical observations were
written and sealed before this diagnostic opened build-reference components.
The current driver only removes an unused lint directive after execution; the
exact executed driver is retained beside the freeze.
Its payload helper contract is the R108 source at `59e307a`, before the R109
type-surface change; use that revision when replaying these historical physical
observations. The completed namespace deliberately refuses replacement.

`physical-observations.json` contains 197 `/app` manifest observations, their
actual manifest SHA256, exact name/version agreement, nearest containing package,
conventional Node installation slot, current decision and actual code/type file
bytes. Inspection took 4.109 seconds and did not execute or install a project.
`post-reference-diagnostic.json` is a separate, subsequent reference join.

| Project | Canonical installed-slot observations | Root manifest | Embedded local package observations |
|---|---:|---:|---:|
| Axios | 8 | 1 | 7 |
| Fastify | 47 | 1 | 4 |
| Pino | 12 | 1 | 1 |
| Nest starter | 114 | 1 | 0 |

Observation counts are not unique component or TP counts. For example, three
Axios directories carry the same `ts-entrypoint-test@1.0.0` identity. The existing
five Axios, three Fastify and one Pino reference extras account for twelve
physical embedded observations. Every one has exact manifest identity plus
actual delivered JavaScript/TypeScript file bytes. Axios packages are under
`/app/test/module/*`; Fastify contains manifests under `fast-uri/benchmark`,
`secure-json-parse/benchmarks` and `pino/test/fixtures/transport`; Pino contains
the same transport unit under `/app/test/fixtures`. Their nearest parent
packages are recorded. The `benchmark` manifest is private, but other examples
are not: `private` is not a generic exclusion rule.

These extras are not proof that the files or package units are absent from the
image. The native build SBOM describes installed dependency instances; it omits
these copied local units. Dropping delivered unit inventory solely to match that
scope would hide real image contents. No installed-only metric is substituted
for the original conservative 306/9/1 score. A later separately labelled
installed-dependency view can coexist with full delivered inventory and show
embedded/local units with their containing owner. It must not claim registry
package authenticity, application reachability, execution or directness.

Nest's missing `@tokenizer/token@0.3.0` is a distinct, demonstrated gap. It has an
exact scoped canonical installation slot, a 700-byte actual manifest with
`main: ""`, `types: "index.d.ts"`, and an actual 886-byte `index.d.ts`:

```
manifest SHA256 a677763aaed22462b4f9df2526b1038cef3a90bc6cf80be27b4e65d0f14472a9
types SHA256    e46cf250ea18d419593c3d20e3cab8465158dd7b891a46f30ca382a109a55131
```

The current `_javascript` function intentionally excludes `.d.ts` and finds no
code/resource witness, so this package remains `PAYLOAD_NOT_CONFIRMED`. Its
type declaration bytes are present. A separate delivered-type component
presence can cover it without pretending that JavaScript code or runtime use
exists. Do not merely remove the `.d.ts` exclusion and relabel types as code.

## Generic follow-up hypotheses, not implemented rules

1. Add a non-destructive npm location/owner axis: root application,
   canonical installed slot, explicitly established workspace/local package,
   embedded package unit, or UNKNOWN. Match a conventional installed slot to the
   exact manifest name (including scope), using the last `node_modules` boundary;
   do not blacklist `test`, `fixtures`, `benchmark`, package names or `private`.
   Keep all delivered component units in the full image inventory. A selected
   dependency view must expose its scope, embedded exclusions and UNKNOWN
   coverage, with separate fixed truth labels.
2. Add explicit type-declaration delivery evidence: exact physical manifest
   identity plus bounded, regular, in-owner declaration bytes selected by
   `types`/`typings` or supported exports. Bind to actual final file path/layer,
   image config and the artifact instance; seal hashes internally. Preserve
   `observed_code_payload=unconfirmed` and state that these are declarations.
3. Node layout is evidence, not a complete ownership resolver. Aliased npm
   packages, pnpm stores, workspace symlinks, Yarn PnP, standalone application
   roots and packages copied outside `node_modules` need explicit supported
   evidence or UNKNOWN. The current diagnosis did not establish general
   workspace or symlink resolution.

Required tests before any production change: retained nested `node_modules`
and scoped package slots; same-name multiple versions; npm alias paths without
identity guessing; local/workspace packages inside and outside conventional
slots; pnpm store and Yarn PnP unsupported/UNKNOWN behavior; symlink traversal,
whiteout/final-layer, duplicate final path and stale-envelope failures; nested
owner file theft; malformed/duplicate manifest keys and identity/version
disagreement; escaping/absolute `types`, empty/missing/oversized declaration,
types-only package, export condition boundaries and fake copied manifests;
per-artifact same-PURL sibling isolation. Freeze any new candidate before
measurements. Keep the existing full inventory, failure and no-lock regression
views; these exposed projects cannot become fresh controls after tuning.

Existing runtime scores remain unchanged. Original R106 Chalk publication
PermissionError is not diagnosed or claimed fixed by this work.

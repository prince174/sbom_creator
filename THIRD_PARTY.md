# Provenance and third-party schemas

Design and validation approach adapted from `G:\code\SCA_accuracy_improvement`,
commit `5ea0b0f9957cae983f53d740f18f1431c70fe729` (Apache-2.0).
The prior service remains untouched.

Bundled schemas are unmodified upstream files fetched on 2026-09-29:

- Syft 1.51.1 / JSON schema 16.1.10:
  https://github.com/anchore/syft/blob/v1.51.1/schema/json/schema-16.1.10.json
- CycloneDX 1.6, SPDX license and JSF schemas:
  https://github.com/CycloneDX/specification/tree/1.6/schema

Syft is Apache-2.0. CycloneDX schemas include their own copyright/license metadata.
Runtime validation is offline; external schema retrieval is disabled by the registry.

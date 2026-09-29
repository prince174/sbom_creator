"""Evidence-preserving reconciliation of source and delivered-image Syft catalogs.

This policy describes package inventory, never runtime use or CVE applicability.
Rules are the default policy. Optional model assessment never replaces missing
image evidence. Source-only declarations and non-exact identities remain UNKNOWN.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl

from packageurl import PackageURL

from .payload import SUPPORTED as PAYLOAD_CATALOGERS

TP_THRESHOLD = 70
POLICY_VERSION = "image-evidence-tp-gt-70-v3"
RULES_POLICY_VERSION = "image-evidence-and-payload-v3"
TYPE_ALIASES = {
    "java-archive": "maven", "python": "pypi", "rust-crate": "cargo",
    "go-module": "golang", "gem": "gem", "npm": "npm",
}
_RANGE = re.compile(r"[\s*<>=|,\[\]()]")
_DIRECT_CATALOGERS = {
    "java-archive-cataloger": "archive_metadata",
    "java-jvm-cataloger": "binary_metadata",
    "graalvm-native-image-cataloger": "binary_metadata",
    "go-module-binary-cataloger": "binary_metadata",
    "cargo-auditable-binary-cataloger": "binary_metadata",
    "python-installed-package-cataloger": "package_metadata",
    "javascript-package-cataloger": "package_metadata",
    "ruby-installed-gemspec-cataloger": "package_metadata",
    "pe-binary-package-cataloger": "binary_metadata",
    "elf-binary-package-cataloger": "binary_metadata",
    "dpkg-db-cataloger": "package_metadata",
    "rpm-db-cataloger": "package_metadata",
    "apk-db-cataloger": "package_metadata",
    "alpm-db-cataloger": "package_metadata",
    "portage-cataloger": "package_metadata",
    "nix-cataloger": "package_metadata",
}


def checksum(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _exact_version(version: Any) -> bool:
    return (isinstance(version, str) and bool(version)
            and version.lower() not in {"unknown", "latest", "unspecified", "none"}
            and not version.startswith(("~", "^"))
            and not _RANGE.search(version))


def _canonical(purl: PackageURL) -> PackageURL:
    # PEP 503 normalization includes dots and runs of separators. Some releases
    # of packageurl-python normalize underscores only.
    if purl.type == "pypi":
        purl = purl._replace(name=re.sub(r"[-_.]+", "-", purl.name).lower())
    return PackageURL.from_string(purl.to_string())


def artifact_identity(artifact: dict) -> dict:
    """Prefer complete PURL, then exact type/namespace/name/version; never fuzzy."""
    raw_purl = artifact.get("purl")
    artifact_version = artifact.get("version")
    try:
        if raw_purl:
            if not isinstance(raw_purl, str) or any(ord(c) < 32 for c in raw_purl):
                raise ValueError("Malformed PURL")
            query = raw_purl.partition("?")[2].partition("#")[0]
            keys = [k.lower() for k, _ in parse_qsl(query, keep_blank_values=True)]
            if len(keys) != len(set(keys)):
                raise ValueError("Duplicate PURL qualifier")
            purl = _canonical(PackageURL.from_string(raw_purl))
            go_stdlib = (artifact.get("type") == "go-module" and artifact.get("name") == "stdlib"
                         and artifact.get("foundBy") == "go-module-binary-cataloger"
                         and purl.type == "golang" and purl.name == "stdlib" and not purl.namespace
                         and isinstance(purl.version, str) and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", purl.version)
                         and artifact_version == "go" + purl.version)
            if artifact_version and artifact_version != purl.version and not go_stdlib:
                raise ValueError("Artifact and PURL versions disagree")
            artifact_type = TYPE_ALIASES.get(artifact.get("type"), artifact.get("type"))
            binary_generic = artifact_type == "binary" and purl.type == "generic"
            if artifact_type and artifact_type != purl.type and not binary_generic:
                raise ValueError("Artifact ecosystem and PURL type disagree")
            artifact_name = artifact.get("name")
            if artifact_name:
                name_options = {purl.name, f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name}
                if purl.type == "maven" and purl.namespace:
                    name_options.add(f"{purl.namespace}:{purl.name}")
                if purl.type == "pypi":
                    artifact_name = re.sub(r"[-_.]+", "-", artifact_name).lower()
                elif purl.type == "npm":
                    artifact_name = artifact_name.lower()
                if artifact_name not in name_options:
                    raise ValueError("Artifact name and PURL name disagree")
        else:
            ecosystem = TYPE_ALIASES.get(artifact.get("type"), artifact.get("type"))
            name = artifact.get("name")
            namespace = artifact.get("namespace") or artifact.get("group") or ""
            metadata = artifact.get("metadata") or {}
            if ecosystem == "maven" and not namespace:
                namespace = (metadata.get("pomProperties") or {}).get("groupId", "")
            if not isinstance(ecosystem, str) or not ecosystem or not isinstance(name, str) or not name:
                raise ValueError("Missing ecosystem or package name")
            if ecosystem == "maven" and not namespace:
                raise ValueError("Maven fallback identity requires a namespace")
            if ecosystem == "npm" and name.startswith("@") and "/" in name:
                namespace, name = name.rsplit("/", 1)
            if ecosystem == "golang" and "/" in name and not namespace:
                namespace, name = name.rsplit("/", 1)
            purl = _canonical(PackageURL(ecosystem, namespace, name, artifact_version))
        if not _exact_version(purl.version):
            raise ValueError("Version is missing or is a version constraint")
        if not purl.name or (purl.type == "maven" and not purl.namespace):
            raise ValueError("Incomplete package identity")
        # Qualifiers and subpath are deliberately retained. Different architecture,
        # distribution, namespace, or version must not silently collapse.
        identity = purl.to_string()
        package = purl._replace(version=None).to_string()
        return {"identity": identity, "package_key": package, "version": purl.version,
                "identity_valid": True, "identity_problem": None,
                "identity_method": "purl" if raw_purl else "exact_fallback"}
    except (ValueError, TypeError, AttributeError) as exc:
        return {"identity": raw_purl if isinstance(raw_purl, str) else None,
                "package_key": None, "version": artifact_version,
                "identity_valid": False, "identity_problem": str(exc),
                "identity_method": "ambiguous"}


def _presence_kind(artifact: dict) -> str:
    cataloger = artifact.get("foundBy", "")
    if cataloger in _DIRECT_CATALOGERS:
        return _DIRECT_CATALOGERS[cataloger]
    if cataloger == "python-package-cataloger" or any(word in cataloger for word in ("lock", "requirements", "pom", "gemfile", "gemspec")):
        return "declared_manifest"
    return "unclassified_observation"


def _validate_artifacts(document: dict, origin: str) -> list[dict]:
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise TypeError(f"{origin} Syft document requires an artifacts array")
    ids = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("id"), str) or not artifact["id"]:
            raise ValueError(f"{origin} artifact requires a nonempty string ID")
        ids.append(artifact["id"])
    if len(ids) != len(set(ids)):
        raise ValueError(f"{origin} Syft artifact IDs must be unique")
    return artifacts


def build_candidates(source: dict, image: dict, payload_evidence: dict | None = None) -> list[dict]:
    """Create the union of identities; artifact IDs are local to each document."""
    entries: dict[str, dict] = {}
    versions: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for origin, document in (("source", source), ("image", image)):
        artifacts = _validate_artifacts(document, origin)
        document_hash = checksum(document)
        related: dict[str, list] = defaultdict(list)
        for relationship in document.get("artifactRelationships", []):
            for endpoint in (relationship.get("parent"), relationship.get("child")):
                if isinstance(endpoint, str):
                    related[endpoint].append(relationship)
        for artifact in artifacts:
            identity = artifact_identity(artifact)
            key = identity["identity"] if identity["identity_valid"] else f"ambiguous:{origin}:{artifact['id']}"
            if key not in entries:
                entries[key] = {"candidate_id": checksum({"identity_key": key}), **identity,
                                "source_artifact_ids": [], "image_artifact_ids": [], "evidence": []}
            entry = entries[key]
            entry[f"{origin}_artifact_ids"].append(artifact["id"])
            data = {"origin": origin, "document_sha256": document_hash, "artifact_id": artifact["id"],
                    "presence_kind": _presence_kind(artifact), "artifact": copy.deepcopy(artifact),
                    "relationships": copy.deepcopy(related.get(artifact["id"], []))}
            if origin == "image" and payload_evidence is not None and artifact.get("foundBy") in PAYLOAD_CATALOGERS:
                data["payload"] = copy.deepcopy(payload_evidence.get(artifact["id"], {"status": "unconfirmed", "path": None}))
                if data["payload"].get("status") != "confirmed" or not data["payload"].get("path"):
                    data["presence_kind"] = "metadata_without_confirmed_payload"
            entry["evidence"].append({"id": checksum(data), **data})
            if identity["identity_valid"]:
                versions[identity["package_key"]][origin].add(identity["version"])
    for entry in entries.values():
        has_source, has_image = bool(entry["source_artifact_ids"]), bool(entry["image_artifact_ids"])
        entry["match_category"] = ("exact_match" if has_source and has_image else
                                   "image_only" if has_image else "source_only")
        if not entry["identity_valid"]:
            entry["category"] = "ambiguous_identity"
        else:
            observed = versions[entry["package_key"]]
            entry["category"] = ("version_conflict" if observed["source"] and observed["image"]
                                 and observed["source"] != observed["image"] else entry["match_category"])
            entry["observed_versions"] = {origin: sorted(observed[origin]) for origin in ("source", "image")}
    return sorted(entries.values(), key=lambda entry: entry["candidate_id"])


def _image_evidence(candidate: dict) -> list[dict]:
    return [e for e in candidate["evidence"] if e["origin"] == "image"
            and e["presence_kind"] in {"package_metadata", "archive_metadata", "binary_metadata"}]


def rules_assessor(candidates: list[dict]) -> list[dict]:
    """Deterministic evidence-only policy: no scores or model calls."""
    return [{"candidate_id": c["candidate_id"], "tp_score": None,
             "reason": "Exact package identity observed in image metadata; execution is not established."
             if c["identity_valid"] and _image_evidence(c)
             else "Available observations do not establish an exact delivered package identity.",
             "evidence_ids": [e["id"] for e in _image_evidence(c)][:100],
             "missing_evidence": [] if c["identity_valid"] and _image_evidence(c)
             else ["Concrete image package evidence with exact identity/version"]}
            for c in candidates]


def validate_assessments(candidates: list[dict], assessments: Any, *, rules: bool = False) -> dict[str, dict]:
    if not isinstance(assessments, list) or len(assessments) != len(candidates):
        raise ValueError("Exactly one assessment is required for every candidate")
    expected = {candidate["candidate_id"]: candidate for candidate in candidates}
    if len(expected) != len(candidates):
        raise ValueError("Duplicate candidate IDs")
    result = {}
    for assessment in assessments:
        if not isinstance(assessment, dict) or set(assessment) != {
            "candidate_id", "tp_score", "reason", "evidence_ids", "missing_evidence"
        }:
            raise ValueError("Invalid candidate assessment fields")
        cid, score = assessment["candidate_id"], assessment["tp_score"]
        if not isinstance(cid, str) or cid not in expected or cid in result:
            raise ValueError("Unknown or duplicate candidate assessment")
        if rules:
            if score is not None:
                raise ValueError("Rules mode must not assign model TP scores")
        elif type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 100:
            raise ValueError("TP score must be a finite number from 0 to 100")
        if not isinstance(assessment["reason"], str) or not assessment["reason"].strip() or len(assessment["reason"]) > 4000:
            raise ValueError("Assessment requires a bounded nonempty reason")
        ids = assessment["evidence_ids"]
        if (not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(e, str) for e in ids)
                or len(ids) != len(set(ids)) or not set(ids) <= {e["id"] for e in expected[cid]["evidence"]}):
            raise ValueError("Assessment references unknown or duplicate evidence")
        missing = assessment["missing_evidence"]
        if (not isinstance(missing, list) or len(missing) > 20
                or any(not isinstance(e, str) or not e.strip() or len(e) > 1000 for e in missing)):
            raise ValueError("Invalid missing-evidence list")
        result[cid] = copy.deepcopy(assessment)
    return result


def review_report(decisions: list[dict]) -> dict:
    """Compact actionable uncertainty report, without duplicating raw catalogs."""
    actions = {
        "AMBIGUOUS_IDENTITY": "Check original package metadata and exact version; do not guess an identity.",
        "SOURCE_VERSION_NOT_OBSERVED": "Compare source lockfiles with the delivered build; retain the observed image version.",
        "SOURCE_ONLY": "Check whether this is a build/dev dependency, omitted installation, or scanner blind spot.",
        "DECLARATION_ONLY": "Provide installed-package or embedded binary/archive metadata; copied manifests are insufficient.",
        "PAYLOAD_NOT_CONFIRMED": "Inspect package files, RECORD or archive contents; metadata alone is insufficient. Missing support is not proof of absence.",
        "CI_CONFIGURATION": "Review as build/CI configuration; do not treat the action reference as a delivered runtime library.",
    }
    items = []
    for row in decisions:
        if row["decision"] != "UNKNOWN":
            continue
        items.append({
            "candidate_id": row["candidate_id"], "identity": row["identity"],
            "reason": row["review_reason"], "identity_problem": row["identity_problem"],
            "source_artifact_ids": row["source_artifact_ids"],
            "image_artifact_ids": row["image_artifact_ids"],
            "observed_versions": row.get("observed_versions", {}),
            "next_step": actions.get(row["review_reason"], "Inspect original image evidence and scanner coverage."),
        })
    return {"schema_version": 1, "unknown_count": len(items),
            "reason_counts": dict(Counter(x["reason"] for x in items)), "items": items,
            "scope": "Uncertainty review, not proof of absence or non-use; no automatic overrides."}


def reconcile(source: dict, image: dict, assessor: Callable | None = None,
              payload_evidence: dict | None = None) -> dict:
    if assessor is None:
        assessor = rules_assessor
    candidates = build_candidates(source, image, payload_evidence)
    rules = assessor is rules_assessor
    assessments = validate_assessments(candidates, assessor(copy.deepcopy(candidates)), rules=rules)
    included: set[str] = set()
    decisions = []
    for candidate in candidates:
        assessment = assessments[candidate["candidate_id"]]
        image_facts = _image_evidence(candidate)
        cited_image = {e["id"] for e in image_facts} & set(assessment["evidence_ids"])
        if not candidate["identity_valid"]:
            decision, policy_reason = "UNKNOWN", "AMBIGUOUS_IDENTITY"
        elif not image_facts:
            decision, policy_reason = "UNKNOWN", "INSUFFICIENT_IMAGE_EVIDENCE"
        elif not cited_image:
            decision, policy_reason = "UNKNOWN", "NO_CITED_IMAGE_PACKAGE_EVIDENCE"
        elif assessment["missing_evidence"]:
            decision, policy_reason = "UNKNOWN", "MISSING_REQUESTED_EVIDENCE"
        elif rules or assessment["tp_score"] > TP_THRESHOLD:
            decision, policy_reason = "INCLUDE", "EXACT_IMAGE_IDENTITY_SUPPORTED"
        else:
            decision, policy_reason = "EXCLUDE", "TP_SCORE_NOT_ABOVE_THRESHOLD"
        if decision == "INCLUDE":
            # A confirmed identity must not promote lockfile/declaration records
            # carrying the same PURL into installed-package evidence.
            included.update(e["artifact_id"] for e in image_facts)
        ci_only = all(e["origin"] == "source" and e["artifact"].get("foundBy") in {
            "github-actions-usage-cataloger", "github-action-workflow-usage-cataloger"} for e in candidate["evidence"])
        review_reason = (
            "CI_CONFIGURATION" if ci_only else
            "AMBIGUOUS_IDENTITY" if not candidate["identity_valid"] else
            "PAYLOAD_NOT_CONFIRMED" if not image_facts and any(
                e["presence_kind"] == "metadata_without_confirmed_payload" for e in candidate["evidence"]) else
            "SOURCE_VERSION_NOT_OBSERVED" if not image_facts and candidate["category"] == "version_conflict" else
            "SOURCE_ONLY" if not candidate["image_artifact_ids"] else
            "DECLARATION_ONLY" if not image_facts and all(
                e["presence_kind"] == "declared_manifest" for e in candidate["evidence"] if e["origin"] == "image") else
            policy_reason
        )
        decisions.append({**copy.deepcopy(candidate), **assessment, "decision": decision,
                          "policy_reason": policy_reason,
                          "review_reason": review_reason,
                          "selected_image_artifact_ids": [e["artifact_id"] for e in image_facts]
                          if decision == "INCLUDE" else [],
                          "score_kind": "not_scored" if rules else "uncalibrated_model_estimate",
                          "policy_version": RULES_POLICY_VERSION if rules else POLICY_VERSION,
                          "scope": "Inventory policy only; exclusion does not prove absence, runtime non-use, or CVE non-applicability."})
    selected = copy.deepcopy(image)
    selected["artifacts"] = [a for a in selected["artifacts"] if a["id"] in included]
    valid_ids = included | {f["id"] for f in selected.get("files", []) if isinstance(f.get("id"), str)}
    if isinstance(selected.get("source", {}).get("id"), str):
        valid_ids.add(selected["source"]["id"])
    old_relationships = selected.get("artifactRelationships", [])
    selected["artifactRelationships"] = [r for r in old_relationships
                                         if r.get("parent") in valid_ids and r.get("child") in valid_ids]
    counts = Counter(row["decision"] for row in decisions)
    coverage = {
        "mode": "rules" if rules else "llm", "policy_version": RULES_POLICY_VERSION if rules else POLICY_VERSION,
        "source_artifacts": len(source["artifacts"]), "image_artifacts": len(image["artifacts"]),
        "candidates": len(candidates), "selected_artifacts": len(selected["artifacts"]),
        "decisions": {key: counts[key] for key in ("INCLUDE", "EXCLUDE", "UNKNOWN")},
        "categories": dict(Counter(c["category"] for c in candidates)),
        "unknown_reasons": dict(Counter(d["review_reason"] for d in decisions if d["decision"] == "UNKNOWN")),
        "unselected_image_artifacts": len(image["artifacts"]) - len(selected["artifacts"]),
        "payload_verification": "performed" if payload_evidence is not None else "not_provided",
        "relationships_pruned": len(old_relationships) - len(selected["artifactRelationships"]),
        "partial_inventory": counts["UNKNOWN"] > 0,
        "dependency_graph": "Only existing scanner relationships preserved; ownership is not library dependency",
        "runtime_usage": "not_measured", "build_link": "unverified",
        "limitations": ["Non-detection does not establish absence.",
                        "Package metadata can be stale; identity observations are not execution proof.",
                        "Bundling, shading, vendoring and non-auditable Rust binaries may hide components."],
    }
    return {"selected_syft": selected, "decisions": decisions, "coverage": coverage}

"""Read-only independent audit of benchmark reports and published evidence.

Reads a single report snapshot, never runs images, builds, scans or a model, and
never modifies inspected reports/artifacts. JSON audit output goes to stdout.
An optional current-policy check replays only the deterministic rules in memory;
it is consistency validation, not independently labelled accuracy measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from packageurl import PackageURL

from sbom_creator.core import reconcile, rules_assessor
from sbom_creator.validation import validate_cyclonedx, validate_export_identity, validate_syft

LANGUAGES = ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby")
ARTIFACTS = ("source.syft.json", "image.syft.json", "selected.syft.json", "final.cdx.json",
             "decisions.json", "coverage.json", "provenance.json", "summary.json")
COMPLETED = {"completed_rules", "completed_llm"}
SOURCE_EXTENSIONS = {"Java": {".java"}, "JavaScript": {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"},
                     "Python": {".py"}, "Rust": {".rs"}, "Go": {".go"}, "Ruby": {".rb"}}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: object) -> str:
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode())


def normalized_repository(value: str) -> str:
    return value.rstrip("/").removesuffix(".git").lower()


def source_file_inventory(source: Path, language: str) -> dict:
    """Count nonempty tracked language files, excluding metadata/build leftovers.

    This establishes the checkout contains code, not functional correctness or
    production relevance. Untracked generated files cannot turn a fixture into
    a source-bearing repository in the primary 60-case report.
    """
    source = source.resolve(strict=True)
    tracked = subprocess.run(["git", "-C", str(source), "ls-files", "-z"], check=True,
                             capture_output=True, timeout=30).stdout.decode("utf-8", errors="surrogateescape").split("\0")
    counts = Counter()
    for name in tracked:
        relative = Path(name)
        if relative.suffix.lower() not in SOURCE_EXTENSIONS[language] or name.lower().endswith(".d.ts"):
            continue
        path = source / relative
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            continue
        if path.is_file() and path.stat().st_size:
            counts[relative.suffix.lower()] += 1
    return {"tracked_nonempty_language_files": sum(counts.values()), "by_extension": dict(sorted(counts.items())),
            "scope": "Presence of tracked source files; not independently labelled functional correctness"}


def audit_completed(row: dict, work: Path, *, current_policy: bool = False) -> dict:
    result = {"id": row["id"], "status": row["status"], "errors": [], "warnings": [], "checks": {}}

    def check(condition, code, detail=None, *, warning=False):
        if not condition:
            result["warnings" if warning else "errors"].append({"code": code, "detail": detail})

    case = (work / row["id"]).resolve()
    try:
        source_files = source_file_inventory(case / "src", row["language"])
        result["checks"]["source_files"] = source_files
        check(source_files["tracked_nonempty_language_files"] > 0, "CHECKOUT_CONTAINS_NO_TRACKED_LANGUAGE_CODE")
    except (OSError, subprocess.SubprocessError) as exc:
        check(False, "SOURCE_FILE_INVENTORY_FAILED", type(exc).__name__)
    try:
        destination = Path(row["analysis_directory"]).resolve(strict=True)
        if not destination.is_relative_to(case):
            raise ValueError("Published analysis path is outside its benchmark case")
        raw = {name: (destination / name).read_bytes() for name in ARTIFACTS}
        data = {name: json.loads(value) for name, value in raw.items()}
        for name in ("source.syft.json", "image.syft.json", "selected.syft.json"):
            validate_syft(data[name])
        validate_cyclonedx(data["final.cdx.json"])
        validate_export_identity(data["final.cdx.json"], data["selected.syft.json"])
        result["checks"]["schemas"] = True
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result["errors"].append({"code": "ARTIFACT_READ_OR_SCHEMA_FAILURE", "detail": type(exc).__name__})
        return result
    except Exception as exc:  # noqa: BLE001 -- schema errors can contain entire private package records
        result["errors"].append({"code": "ARTIFACT_SCHEMA_FAILURE", "detail": type(exc).__name__})
        return result

    source, image, selected = (data[name] for name in ("source.syft.json", "image.syft.json", "selected.syft.json"))
    final, decisions, coverage, provenance, summary = (data[name] for name in (
        "final.cdx.json", "decisions.json", "coverage.json", "provenance.json", "summary.json"))
    check(isinstance(decisions, list), "DECISIONS_NOT_ARRAY")
    if not isinstance(decisions, list):
        return result
    mode = row["status"].removeprefix("completed_")
    check(row.get("decision_mode") == mode, "REPORT_MODE_MISMATCH")
    check(coverage.get("mode") == mode, "COVERAGE_MODE_MISMATCH")
    check(summary.get("status") == "succeeded" and summary.get("cyclonedx_valid") is True,
          "SUCCESS_SUMMARY_MISSING")
    check(row.get("cyclonedx_valid") is True, "REPORT_VALIDATION_FLAG_MISSING")
    check(not row.get("error"), "COMPLETED_ROW_HAS_ERROR")
    counts = Counter(item.get("decision") for item in decisions)
    check(set(counts) <= {"INCLUDE", "EXCLUDE", "UNKNOWN"}, "UNKNOWN_DECISION_VALUE")
    actual_counts = {"source_count": len(source["artifacts"]), "image_count": len(image["artifacts"]),
                     "final_count": len(final.get("components", [])), "selected_count": len(selected["artifacts"])}
    for key, value in actual_counts.items():
        check(summary.get(key) == value, "SUMMARY_COUNT_MISMATCH", key)
        if key != "selected_count":
            check(row.get(key) == value, "REPORT_COUNT_MISMATCH", key)
    for decision in ("INCLUDE", "EXCLUDE", "UNKNOWN"):
        check(row.get(decision.lower()) == counts[decision], "REPORT_DECISION_COUNT_MISMATCH", decision)
        check(summary.get("decisions", {}).get(decision, 0) == counts[decision], "SUMMARY_DECISION_COUNT_MISMATCH", decision)
        check(coverage.get("decisions", {}).get(decision, 0) == counts[decision], "COVERAGE_DECISION_COUNT_MISMATCH", decision)
    check(summary.get("partial") == coverage.get("partial_inventory"), "PARTIAL_STATUS_MISMATCH")
    if counts["UNKNOWN"] or coverage.get("source_checkout_incomplete"):
        check(summary.get("partial") is True, "INCOMPLETE_INVENTORY_REPORTED_COMPLETE")
    check(row.get("final_sha256") == digest(raw["final.cdx.json"]), "FINAL_HASH_MISMATCH")
    for name in ("source.syft.json", "image.syft.json"):
        check(provenance.get("input_hashes", {}).get(name) == digest(raw[name]), "PROVENANCE_INPUT_HASH_MISMATCH", name)

    by_origin = {"source": {a["id"]: a for a in source["artifacts"]},
                 "image": {a["id"]: a for a in image["artifacts"]}}
    document_digests = {"source": canonical_digest(source), "image": canonical_digest(image)}
    assigned = {"source": [], "image": []}
    candidate_ids, expected_selected = set(), set()
    for decision in decisions:
        cid = decision.get("candidate_id")
        check(isinstance(cid, str) and cid not in candidate_ids, "DUPLICATE_OR_MISSING_CANDIDATE_ID")
        candidate_ids.add(cid)
        for origin in ("source", "image"):
            ids = decision.get(origin + "_artifact_ids", [])
            assigned[origin].extend(ids)
            check(set(ids) <= set(by_origin[origin]), "CANDIDATE_REFERENCES_UNKNOWN_ARTIFACT", origin)
        evidence_by_id = {e["id"]: e for e in decision.get("evidence", [])}
        check(set(decision.get("evidence_ids", [])) <= set(evidence_by_id), "ASSESSMENT_CITES_UNKNOWN_EVIDENCE")
        for evidence_id, evidence in evidence_by_id.items():
            origin = evidence.get("origin")
            check(evidence_id == canonical_digest({k: v for k, v in evidence.items() if k != "id"}), "EVIDENCE_HASH_MISMATCH")
            check(evidence.get("document_sha256") == document_digests.get(origin), "EVIDENCE_DOCUMENT_MISMATCH")
            check(evidence.get("artifact") == by_origin.get(origin, {}).get(evidence.get("artifact_id")), "EVIDENCE_ARTIFACT_MISMATCH")
        if mode == "rules":
            check(decision.get("tp_score") is None and decision.get("score_kind") == "not_scored", "RULES_FABRICATES_MODEL_SCORE")
        if decision.get("decision") == "INCLUDE":
            ids = decision.get("selected_image_artifact_ids", decision.get("image_artifact_ids", []))
            check(bool(ids) and decision.get("identity_valid") is True, "INCLUDED_IDENTITY_NOT_CONFIRMED_IN_IMAGE")
            cited = [evidence_by_id[eid] for eid in decision.get("evidence_ids", []) if eid in evidence_by_id]
            check(any(e.get("origin") == "image" for e in cited), "INCLUSION_WITHOUT_CITED_IMAGE_EVIDENCE")
            expected_selected.update(ids)
    for origin in ("source", "image"):
        check(Counter(assigned[origin]) == Counter(by_origin[origin].keys()), "CANDIDATE_UNION_INCOMPLETE_OR_DUPLICATED", origin)
    selected_ids = {a["id"] for a in selected["artifacts"]}
    check(selected_ids == expected_selected, "SELECTION_DIFFERS_FROM_INCLUDED_DECISIONS")
    check(all(a == by_origin["image"].get(a["id"]) for a in selected["artifacts"]), "SELECTED_ARTIFACT_MUTATED_OR_INVENTED")
    selected_refs = []
    for component in final.get("components", []):
        reference = component.get("bom-ref", "")
        try:
            selected_refs.append(PackageURL.from_string(reference).qualifiers.get("package-id")
                                 if reference.startswith("pkg:") else reference)
        except (ValueError, TypeError):
            selected_refs.append(None)
    check(Counter(selected_refs) == Counter(selected_ids), "CYCLONEDX_PACKAGE_MAPPING_MISMATCH")
    image_provenance = provenance.get("image", {})
    check(image_provenance.get("image_id") == row.get("image_id") and bool(row.get("image_id")), "BUILT_AND_SCANNED_IMAGE_ID_MISMATCH")
    check(image_provenance.get("image_config_digest") == image.get("source", {}).get("metadata", {}).get("imageID"), "SCANNER_IMAGE_CONFIG_MISMATCH")
    check(image_provenance.get("container_started") is False, "PASSIVE_IMAGE_SCAN_NOT_RECORDED", warning=True)
    if image_provenance.get("acquisition") == "local":
        check(image_provenance.get("registry_digest") is None and image_provenance.get("platform_digest") is None,
              "LOCAL_IMAGE_CLAIMS_REGISTRY_DIGEST")
    if row.get("image_digest_kind") == "local image config digest":
        check(row.get("image_id") == image_provenance.get("image_config_digest"), "OCI_INDEX_MISLABELLED_CONFIG_DIGEST")
    check(provenance.get("build_link") == "unverified", "UNSUPPORTED_PRODUCTION_BUILD_LINK_CLAIM")
    git_provenance = provenance.get("git", {})
    if git_provenance:
        check(git_provenance.get("commit") == row.get("commit"), "ANALYZED_COMMIT_MISMATCH")
        if git_provenance.get("repository_url"):
            check(normalized_repository(git_provenance["repository_url"]) == normalized_repository(row["repository_url"]), "ANALYZED_REPOSITORY_MISMATCH")
    else:
        check(False, "PUBLISHED_SOURCE_HAS_NO_COMMIT_PROVENANCE", warning=True)
    if row.get("bitbucket_tested"):
        check(row.get("source_host") == "bitbucket.org", "NON_BITBUCKET_MARKED_AS_BITBUCKET_TESTED")
        check(git_provenance.get("checkout_method") == "git-init-fetch-exact-detached",
              "PRODUCTION_BITBUCKET_CHECKOUT_NOT_EVIDENCED", warning=True)
    head = case / "src" / ".git" / "HEAD"
    check(head.is_file() and head.read_text("utf-8").strip() == row.get("commit"), "BENCHMARK_CHECKOUT_COMMIT_MISMATCH")
    recipe = case / "Dockerfile.benchmark"
    check(recipe.is_file() and digest(recipe.read_bytes()) == row.get("build_recipe_sha256"), "BUILD_RECIPE_HASH_MISMATCH")
    scan = case / "source.syft.json"
    check(scan.is_file() and digest(scan.read_bytes()) == row.get("source_sha256"), "PRELIMINARY_SOURCE_SCAN_HASH_MISMATCH")
    if row.get("fp") is not None or row.get("fn") is not None:
        check(bool(row.get("ground_truth_artifact")) and bool(row.get("ground_truth_scope")), "UNSUPPORTED_ACCURACY_METRICS")
    if current_policy and mode == "rules":
        current = reconcile(source, image, rules_assessor, provenance.get("image", {}).get("payload_evidence"))
        check(current["selected_syft"] == selected, "OUTPUT_STALE_FOR_CURRENT_RULES")
        check(current["decisions"] == decisions, "DECISIONS_STALE_FOR_CURRENT_RULES")
        from sbom_creator.core import review_report
        review = json.loads((destination / "review.json").read_bytes())
        check(review == review_report(current["decisions"], schema_version=review.get("schema_version")), "UNCERTAINTY_REPORT_MISMATCH")
        result["checks"]["current_rules_replayed_in_memory"] = True
    result["checks"].update({"decision_identities": len(decisions), "source_records": actual_counts["source_count"],
                              "image_records": actual_counts["image_count"], "selected_records": actual_counts["selected_count"],
                              "final_records": actual_counts["final_count"], "counts_distinguish_identities_and_records": True,
                              "final_sha256": digest(raw["final.cdx.json"])})
    return result


def audit_report(report_path: Path, manifest_path: Path, work: Path, *, require_all: bool = False,
                 current_policy: bool = False) -> dict:
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    manifest = json.loads(manifest_path.read_bytes())["repositories"]
    rows = report["repositories"]
    errors = []
    if len(rows) != 60 or Counter(r["language"] for r in rows) != Counter({language: 10 for language in LANGUAGES}):
        errors.append("REPORT_REQUIRES_10_PER_LANGUAGE_60_TOTAL")
    if len({r["id"] for r in rows}) != len(rows):
        errors.append("DUPLICATE_CASE_IDS")
    if len({normalized_repository(r["repository_url"]) for r in rows}) != len(rows):
        errors.append("DUPLICATE_REPOSITORIES")
    expected = {r["id"]: r for r in manifest}
    if {r["id"] for r in rows} != set(expected):
        errors.append("REPORT_CASES_DIFFER_FROM_MANIFEST")
    details = []
    for row in rows:
        if any(row.get(key) != expected.get(row["id"], {}).get(key) for key in ("repository_url", "commit", "language")):
            errors.append("REPORT_INPUT_DIFFERS_FROM_MANIFEST:" + row["id"])
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", row.get("commit") or ""):
            errors.append("COMMIT_NOT_PINNED:" + row["id"])
        if row.get("status") in COMPLETED:
            try:
                details.append(audit_completed(row, work, current_policy=current_policy))
            except Exception as exc:  # noqa: BLE001 -- keep auditing other rows without leaking artifact contents
                details.append({"id": row["id"], "status": row["status"], "warnings": [], "checks": {},
                                "errors": [{"code": "AUDIT_ROW_CONTRACT_FAILURE", "detail": type(exc).__name__}]})
        elif require_all:
            errors.append("REPOSITORY_NOT_COMPLETED:" + row["id"])
        if (row.get("fp") is not None or row.get("fn") is not None) and not row.get("ground_truth_artifact"):
            errors.append("UNLABELLED_ACCURACY_METRIC:" + row["id"])
    statuses = {language: dict(Counter(r["status"] for r in rows if r["language"] == language)) for language in LANGUAGES}
    if report.get("summary") != statuses:
        errors.append("REPORT_SUMMARY_MISMATCH")
    failures = sum(bool(row["errors"]) for row in details)
    return {"report": str(report_path.resolve()), "snapshot_sha256": digest(report_bytes),
            "report_generated_at": report.get("generated_at"), "total_repositories": len(rows),
            "completed_rows_audited": len(details), "completed_rows_with_errors": failures,
            "incomplete_rows": len(rows) - len(details), "global_errors": errors, "summary": statuses,
            "audit_passed": not errors and not failures, "requires_all_complete": require_all,
            "scope": "Structural, provenance and consistency audit; not an FP/FN accuracy measurement",
            "repositories": details}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks" / "manifest.json")
    parser.add_argument("--work", type=Path, default=ROOT / "benchmarks" / ".work")
    parser.add_argument("--require-all-complete", action="store_true")
    parser.add_argument("--check-current-policy", action="store_true")
    args = parser.parse_args()
    result = audit_report(args.results.resolve(), args.manifest.resolve(), args.work.resolve(),
                          require_all=args.require_all_complete, current_policy=args.check_current_policy)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

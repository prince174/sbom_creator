"""Validated, atomic publication of a single source/image analysis."""
import hashlib
import json
import shutil
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .acquire import (
    Settings,
    checkout,
    clean_environment,
    inspect_checkout,
    run_command,
    validate_commit,
    validate_inputs,
)
from .core import reconcile, review_report, rules_assessor
from .exporter import packages_only
from .llm import LlmConfig, OpenAICompatibleAssessor
from .payload import SUPPORTED as PAYLOAD_CATALOGERS
from .scanner import convert, scan_image, scan_source
from .validation import validate_cyclonedx, validate_export_identity, validate_syft

ARTIFACTS = (
    "final.cdx.json", "source.syft.json", "image.syft.json", "selected.syft.json",
    "decisions.json", "coverage.json", "provenance.json", "summary.json", "review.json",
)


class AnalysisError(RuntimeError):
    def __init__(self, stage, error_type):
        self.stage = stage
        self.error_type = error_type
        super().__init__(f"{stage} failed ({error_type})")


def diagnostic(output, stage, error):
    target = Path(output).resolve().with_name(Path(output).name + ".diagnostics")
    try:
        target.mkdir(parents=True)
    except FileExistsError:
        # A retry must neither replace earlier evidence nor attach its old scans
        # to a newer error. mkdtemp also makes concurrent failure paths distinct.
        target = Path(tempfile.mkdtemp(prefix=target.name + "-", dir=target.parent))
    write_json(target / "failure.json", {"status": "failed", "stage": stage,
               "error_type": type(error).__name__, "final_published": False})
    return target


@contextmanager
def analysis_workspace(output):
    """Preserve completed scans before cleanup, and expose only safe error fields."""
    destination = Path(output).resolve()
    if destination.exists():
        raise FileExistsError("Output directory already exists; choose a new analysis path")
    with tempfile.TemporaryDirectory(prefix="sbom-job-") as temporary:
        work = Path(temporary)
        state = {"work": work, "stage": "configuration", "provenance": {}}
        try:
            yield state
        except AnalysisError:
            # Publication already preserved both input catalogs and its own stage.
            raise
        except Exception as error:
            if isinstance(error, FileExistsError) and destination.exists():
                raise
            target = diagnostic(destination, state["stage"], error)
            for name in ("source.syft.json", "image.syft.json"):
                if (work / name).is_file():
                    shutil.copyfile(work / name, target / name)
            write_json(target / "provenance.json", state["provenance"])
            raise AnalysisError(state["stage"], type(error).__name__) from None


def write_json(path, data):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    for attempt in range(20):
        try:
            temp.replace(path)
            break
        except PermissionError:
            if attempt == 19:
                raise
            # Windows readers/antivirus can transiently deny an atomic replacement.
            time.sleep(0.025)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assessor_for(mode):
    if mode == "rules":
        return rules_assessor
    if mode != "llm":
        raise ValueError("Mode must be llm or explicit rules")
    return OpenAICompatibleAssessor(LlmConfig.from_environment())


def catalogers(document):
    configured = document.get("descriptor", {}).get("configuration", {}).get("catalogers", {})
    used = configured.get("used", []) if isinstance(configured, dict) else []
    return sorted({a["foundBy"] for a in document["artifacts"]} | set(used or []))


def _publish_catalogs(source, image, output, settings, assessor, provenance=None):
    """Also serves benchmark/replay; schemas and actual conversion always checked."""
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Output directory already exists; choose a new analysis path")
    output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    validate_syft(source)
    validate_syft(image)
    payload_evidence = (provenance or {}).get("image", {}).get("payload_evidence")
    result = reconcile(source, image, assessor, payload_evidence)
    validate_syft(result["selected_syft"])
    with tempfile.TemporaryDirectory(prefix=".publish-", dir=output.parent) as temporary:
        staging = Path(temporary) / "result"
        staging.mkdir()
        write_json(staging / "source.syft.json", source)
        write_json(staging / "image.syft.json", image)
        write_json(staging / "selected.syft.json", result["selected_syft"])
        provenance = dict(provenance or {})
        provenance.update({
            "created_at": datetime.now(UTC).isoformat(),
            "build_link": provenance.get("build_link", "unverified"),
            "syft_version": "1.51.1", "syft_schema": "16.1.10",
            "sbom_creator_version": __version__,
            "assessment": getattr(assessor, "audit", {
                "mode": "rules" if assessor is rules_assessor else "external-assessor",
                "score": None, "verified_model": False}),
            "input_hashes": {name: sha256(staging / name)
                             for name in ("source.syft.json", "image.syft.json")},
        })
        cdx = convert(staging / "selected.syft.json", staging / "final.cdx.json", settings)
        cdx = packages_only(cdx, result["selected_syft"])
        validate_export_identity(cdx, result["selected_syft"])
        counts = Counter(d["decision"] for d in result["decisions"])
        cdx.setdefault("metadata", {}).setdefault("properties", []).extend([
            {"name": "sbom-creator:build-link", "value": provenance["build_link"]},
            {"name": "sbom-creator:runtime-execution", "value": "not-assessed"},
            {"name": "sbom-creator:unknown-count", "value": str(counts.get("UNKNOWN", 0))},
            {"name": "sbom-creator:provenance", "value": json.dumps(provenance, ensure_ascii=False)},
        ])
        coverage = result["coverage"]
        checkout_coverage = provenance.get("git", {}).get("coverage", provenance.get("source_coverage", {}))
        incomplete_source = bool(checkout_coverage.get("gitmodules_present")
                                 or checkout_coverage.get("lfs_pointer_paths"))
        coverage.update({"runtime_execution": "not_assessed", "absence_proven": False,
                         "dependency_graph_complete": False,
                         "source_coverage": checkout_coverage,
                         "source_checkout_incomplete": incomplete_source,
                         "source_catalogers": catalogers(source),
                         "image_catalogers": catalogers(image)})
        payload_unavailable = payload_evidence is None and any(
            a.get("foundBy") in PAYLOAD_CATALOGERS for a in image["artifacts"])
        coverage["partial_inventory"] = counts.get("UNKNOWN", 0) > 0 or incomplete_source or payload_unavailable
        cdx["metadata"]["properties"].extend([
            {"name": "sbom-creator:assessment-mode", "value": coverage["mode"]},
            {"name": "sbom-creator:policy-version", "value": coverage["policy_version"]},
            {"name": "sbom-creator:coverage", "value": "partial" if coverage["partial_inventory"] else "no-known-gaps"},
            {"name": "sbom-creator:payload-verification", "value": coverage["payload_verification"]},
        ])
        validate_cyclonedx(cdx)
        write_json(staging / "final.cdx.json", cdx)
        summary = {
            "status": "succeeded", "partial": coverage["partial_inventory"],
            "assessment_mode": coverage["mode"], "policy_version": coverage["policy_version"],
            "payload_verification": coverage["payload_verification"],
            "unknown_reasons": coverage["unknown_reasons"],
            "source_count": len(source["artifacts"]), "image_count": len(image["artifacts"]),
            "selected_count": len(result["selected_syft"]["artifacts"]),
            "final_count": len(cdx.get("components", [])),
            "decisions": dict(counts), "cyclonedx_valid": True,
            "reconciliation_seconds": round(time.monotonic() - started, 3),
        }
        write_json(staging / "decisions.json", result["decisions"])
        write_json(staging / "coverage.json", coverage)
        write_json(staging / "provenance.json", provenance)
        write_json(staging / "summary.json", summary)
        write_json(staging / "review.json", review_report(result["decisions"]))
        staging.rename(output)
    return summary


def publish_catalogs(source, image, output, settings, assessor, provenance=None):
    try:
        return _publish_catalogs(source, image, output, settings, assessor, provenance)
    except FileExistsError:
        raise
    except Exception as error:  # noqa: BLE001 -- safe diagnostic boundary
        target = diagnostic(output, "reconcile_convert_validate", error)
        write_json(target / "source.syft.json", source)
        write_json(target / "image.syft.json", image)
        write_json(target / "provenance.json", provenance or {})
        raise AnalysisError("reconcile_convert_validate", type(error).__name__) from None


def analyze_local(source_path, image_reference, output, settings=None, mode="rules"):
    with analysis_workspace(output) as state:
        work = state["work"]
        settings = settings or Settings.from_env()
        state["stage"] = "assessment_configuration"
        assessor = assessor_for(mode)  # Fail before network/scanning if model is unconfigured.
        state["provenance"] = {"mode": mode, "source_kind": "local-checkout"}
        state["stage"] = "source_inspection"
        checkout_path = Path(source_path).resolve()
        source_coverage = inspect_checkout(checkout_path, settings)
        git_provenance = {"coverage": source_coverage, "commit": None, "source_kind": "local-directory"}
        if (checkout_path / ".git").exists():
            commit = run_command([settings.git_binary, "-c", "core.fsmonitor=false", "rev-parse", "HEAD"],
                                 cwd=checkout_path, env=clean_environment(), timeout=30,
                                 max_output_bytes=4096, label="Local Git revision")
            git_provenance.update(commit=validate_commit(commit.strip()), source_kind="local-checkout",
                                  commit_verification="HEAD only; local modifications not verified")
        state["provenance"].update(source_coverage=source_coverage, git=git_provenance)
        state["stage"] = "source_scan"
        source = scan_source(checkout_path, work / "source.syft.json", settings)
        state["stage"] = "image_scan"
        image, image_provenance = scan_image(image_reference, work / "image.syft.json", settings)
        state["provenance"]["image"] = image_provenance
        state["stage"] = "publication"
        return publish_catalogs(source, image, output, settings, assessor, state["provenance"])


def analyze(repository_url, commit, image_reference, output, settings=None, mode="rules"):
    with analysis_workspace(output) as state:
        work = state["work"]
        settings = settings or Settings.from_env()
        state["stage"] = "input_validation"
        validate_inputs(repository_url, commit, image_reference, settings)
        # Input validation excludes embedded credentials before recording requests.
        state["provenance"] = {"mode": mode, "request": {"repository_url": repository_url,
                                 "commit": commit, "image": image_reference}}
        state["stage"] = "assessment_configuration"
        assessor = assessor_for(mode)
        state["stage"] = "checkout"
        git_provenance = checkout(repository_url, commit, work / "checkout", settings)
        state["provenance"]["git"] = git_provenance
        state["stage"] = "source_scan"
        source = scan_source(work / "checkout", work / "source.syft.json", settings)
        state["stage"] = "image_scan"
        image, image_provenance = scan_image(image_reference, work / "image.syft.json", settings)
        state["provenance"]["image"] = image_provenance
        state["stage"] = "publication"
        return publish_catalogs(source, image, output, settings, assessor, state["provenance"])

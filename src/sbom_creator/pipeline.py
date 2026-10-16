"""Validated, atomic publication of a single source/image analysis."""
import copy
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
from .build_backend import resolve as resolve_java
from .build_comparison import compare as compare_build_image
from .core import reconcile, review_report, rules_assessor
from .direct_evidence import annotate, load_manifest
from .exporter import packages_only, split_inventory
from .java_evidence import annotate as annotate_java
from .llm import LlmConfig, OpenAICompatibleAssessor
from .payload import SUPPORTED as PAYLOAD_CATALOGERS
from .publication import (
    ERROR_TYPES,
    PublicationState,
    commit_directory,
    error_code,
    error_type_name,
    safe_details,
    staging_directory,
)
from .python_evidence import annotate as annotate_python
from .python_evidence import combine
from .python_inputs import load_manifest as load_python_manifest
from .scanner import convert, scan_image, scan_source
from .validation import validate_cyclonedx, validate_export_identity, validate_syft

ARTIFACTS = (
    "final.cdx.json", "source.syft.json", "image.syft.json", "selected.syft.json",
    "decisions.json", "coverage.json", "provenance.json", "summary.json", "review.json",
    "os.cdx.json", "full.cdx.json",
    "direct-dependencies.json",
    "java-direct-dependencies.json",
)
OPTIONAL_ARTIFACTS = ('build.cdx.json', 'image.cdx.json', 'build-image-comparison.json',
                      'image-original.syft.json', 'image-peer.cdx.json', 'image-identity-audit.json')
ANALYSIS_STAGES = frozenset({'configuration', 'assessment_configuration', 'source_inspection',
    'source_scan', 'java_source_dependencies', 'image_scan', 'publication', 'input_validation',
    'checkout', 'reconcile_convert_validate', 'verification', 'analysis', 'acquisition_or_configuration'})


class AnalysisError(RuntimeError):
    def __init__(self, stage, error_type, *, publication=None):
        self.stage = stage if type(stage) is str and stage in ANALYSIS_STAGES else 'acquisition_or_configuration'
        self.error_type = error_type if type(error_type) is str and error_type in ERROR_TYPES else 'Exception'
        self.publication = safe_details(publication)
        super().__init__(f"{self.stage} failed ({self.error_type})")


def publication_details(error):
    return safe_details(error.publication) if type(error) is AnalysisError else {}


def error_fields(error, fallback_stage='acquisition_or_configuration'):
    fallback_stage = fallback_stage if type(fallback_stage) is str and fallback_stage in ANALYSIS_STAGES else 'acquisition_or_configuration'
    if type(error) is not AnalysisError:
        return {'stage': fallback_stage, 'error_type': error_type_name(error)}
    stage = error.stage if type(error.stage) is str and error.stage in ANALYSIS_STAGES else fallback_stage
    kind = error.error_type if type(error.error_type) is str and error.error_type in ERROR_TYPES else 'Exception'
    return {'stage': stage, 'error_type': kind, **publication_details(error)}


def diagnostic(output, stage, error, publication=None):
    target = Path(output).resolve().with_name(Path(output).name + ".diagnostics")
    try:
        target.mkdir(parents=True)
    except FileExistsError:
        # A retry must neither replace earlier evidence nor attach its old scans
        # to a newer error. mkdtemp also makes concurrent failure paths distinct.
        target = Path(tempfile.mkdtemp(prefix=target.name + "-", dir=target.parent))
    write_json(target / "failure.json", failure_record(stage, error, publication))
    return target


def failure_record(stage, error, publication=None):
    if publication is not None:
        publication.capture(error)
    fields = publication.details() if publication is not None else {}
    return {"status": "failed", "stage": stage,
        "error_type": publication.failure['error_type'] if publication is not None else error_type_name(error),
        "final_published": fields.get('publication_committed', False), **fields}


@contextmanager
def _analysis_temporary_directory():
    temporary = tempfile.TemporaryDirectory(prefix='sbom-job-')
    failure = None
    try:
        try:
            yield temporary.name
        except AnalysisError as error:
            failure = error
            raise
    finally:
        try:
            temporary.cleanup()
        except Exception as error:
            if failure is None:
                raise
            failure.publication = safe_details({**publication_details(failure),
                'workspace_cleanup_error_code': error_code(error)})


@contextmanager
def analysis_workspace(output):
    """Preserve completed scans before cleanup, and expose only safe error fields."""
    destination = Path(output).resolve()
    if destination.exists():
        raise FileExistsError("Output directory already exists; choose a new analysis path")
    with _analysis_temporary_directory() as temporary:
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


def _publish_catalogs(source, image, output, settings, assessor, provenance=None, npm_manifest=None, python_manifest=None, java_report=None, publication_state=None):
    """Also serves benchmark/replay; schemas and actual conversion always checked."""
    state = publication_state if publication_state is not None else PublicationState()
    def write_artifact(path, data):
        state.mark('write_artifact', Path(path).name)
        write_json(path, data)
    output = Path(output).resolve()
    if output.exists():
        state.refused_existing_output = True
        raise FileExistsError("Output directory already exists; choose a new analysis path")
    output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    state.mark('validate_catalogs')
    validate_syft(source)
    validate_syft(image)
    payload_evidence = (provenance or {}).get("image", {}).get("payload_evidence")
    identity_envelope = (provenance or {}).get('image', {}).get('identity_binding_envelope')
    state.mark('reconcile')
    result = reconcile(source, image, assessor, payload_evidence, identity_envelope)
    state.mark('validate_selection')
    validate_syft(result["selected_syft"])
    with staging_directory(output.parent, state) as temporary:
        staging = Path(temporary) / "result"
        staging.mkdir()
        write_artifact(staging / "source.syft.json", source)
        write_artifact(staging / "image.syft.json", image)
        write_artifact(staging / "selected.syft.json", result["selected_syft"])
        state.mark('build_provenance')
        provenance = dict(provenance or {})
        provenance['image'] = dict(provenance.get('image', {}))
        auxiliary = provenance['image'].pop('_artifacts', {})
        for name, document in auxiliary.items():
            state.mark('build_provenance')
            if name not in OPTIONAL_ARTIFACTS:
                raise ValueError('Unrecognized image evidence artifact')
            write_artifact(staging/name, document)
        state.mark('build_provenance')
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
        state.mark('convert_final', 'final.cdx.json')
        cdx = convert(staging / "selected.syft.json", staging / "final.cdx.json", settings)
        state.mark('validate_final_identity', 'final.cdx.json')
        cdx = packages_only(cdx, result["selected_syft"])
        validate_export_identity(cdx, result["selected_syft"])
        state.mark('annotate_dependencies')
        direct = annotate(cdx, image, npm_manifest)
        if python_manifest is not None:
            direct = combine(direct, annotate_python(cdx, image, python_manifest))
        java_report = copy.deepcopy(java_report) if java_report is not None else None
        build_bom = java_report.pop('build_sbom', None) if java_report else None
        if build_bom is not None:
            state.mark('compare_build_image')
            validate_cyclonedx(build_bom)
            write_artifact(staging / 'build.cdx.json', build_bom)
            state.mark('compare_build_image', 'image.cdx.json')
            image_bom = packages_only(convert(staging / 'image.syft.json', staging / 'image.cdx.json', settings), image)
            validate_cyclonedx(image_bom)
            write_artifact(staging / 'image.cdx.json', image_bom)
            state.mark('compare_build_image')
            write_artifact(staging / 'build-image-comparison.json', compare_build_image(build_bom, image_bom))
            java_report['build_artifact'] = 'build.cdx.json'
        state.mark('annotate_dependencies')
        java_report = annotate_java(cdx, java_report or {
            "status": "not-applicable", "reason": "source_poms_not_provided", "edges": [],
            "profile": "java-maven-source-modules-v1", "graph_complete": False})
        write_artifact(staging / "java-direct-dependencies.json", java_report)
        direct = combine(direct, java_report)
        write_artifact(staging / "direct-dependencies.json", direct)
        state.mark('prepare_coverage')
        counts = Counter(d["decision"] for d in result["decisions"])
        cdx.setdefault("metadata", {}).setdefault("properties", []).extend([
            {"name": "sbom-creator:build-link", "value": provenance["build_link"]},
            {"name": "sbom-creator:runtime-execution", "value": "not-assessed"},
            {"name": "sbom-creator:unknown-count", "value": str(counts.get("UNKNOWN", 0))},
            {"name": "sbom-creator:provenance", "value": json.dumps(provenance, ensure_ascii=False)},
        ])
        coverage = result["coverage"]
        coverage["direct_dependencies"] = {k: v for k, v in direct.items() if k != "edges"}
        coverage['java_dependencies'] = {k: java_report.get(k) for k in
            ('status', 'profile', 'direct_count', 'unknown_count', 'original_build_reproduced', 'reason')}
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
        coverage["partial_inventory"] = (counts.get("UNKNOWN", 0) > 0 or incomplete_source or payload_unavailable
                                         or java_report['status'] == 'UNKNOWN'
                                         or provenance.get('image', {}).get('java_image_status') == 'UNKNOWN')
        cdx["metadata"]["properties"].extend([
            {"name": "sbom-creator:assessment-mode", "value": coverage["mode"]},
            {"name": "sbom-creator:policy-version", "value": coverage["policy_version"]},
            {"name": "sbom-creator:coverage", "value": "partial" if coverage["partial_inventory"] else "no-known-gaps"},
            {"name": "sbom-creator:payload-verification", "value": coverage["payload_verification"]},
        ])
        state.mark('validate_final', 'full.cdx.json')
        validate_cyclonedx(cdx)
        state.mark('split_inventory')
        application_cdx, os_cdx = split_inventory(cdx, result["selected_syft"])
        write_artifact(staging / "full.cdx.json", cdx)
        write_artifact(staging / "os.cdx.json", os_cdx)
        write_artifact(staging / "final.cdx.json", application_cdx)
        state.mark('prepare_coverage')
        review = review_report(result["decisions"])
        summary = {
            "status": "succeeded", "partial": coverage["partial_inventory"],
            "assessment_mode": coverage["mode"], "policy_version": coverage["policy_version"],
            "payload_verification": coverage["payload_verification"],
            "unknown_reasons": coverage["unknown_reasons"],
            "unknown_groups": review["group_counts"],
            "source_count": len(source["artifacts"]), "image_count": len(image["artifacts"]),
            "selected_count": len(result["selected_syft"]["artifacts"]),
            "final_count": len(application_cdx.get("components", [])),
            "os_count": len(os_cdx.get("components", [])),
            "full_count": len(cdx.get("components", [])),
            "inventory_scope": "non-os-packages-v1",
            "decisions": dict(counts), "cyclonedx_valid": True,
            "reconciliation_seconds": round(time.monotonic() - started, 3),
        }
        write_artifact(staging / "decisions.json", result["decisions"])
        write_artifact(staging / "coverage.json", coverage)
        write_artifact(staging / "provenance.json", provenance)
        write_artifact(staging / "summary.json", summary)
        write_artifact(staging / "review.json", review)
        state.mark('commit_directory')
        commit_directory(staging, output)
        state.committed = True
    return summary


def publish_catalogs(source, image, output, settings, assessor, provenance=None, npm_manifest=None, python_manifest=None, java_report=None):
    state = PublicationState()
    try:
        return _publish_catalogs(source, image, output, settings, assessor, provenance, npm_manifest, python_manifest, java_report, state)
    except Exception as error:
        if isinstance(error, FileExistsError) and state.refused_existing_output:
            raise
        state.capture(error)
        target = None
        state.diagnostics_status = 'partial'
        try:
            target = diagnostic(output, "reconcile_convert_validate", error, state)
            write_json(target / "source.syft.json", source)
            write_json(target / "image.syft.json", image)
            write_json(target / "provenance.json", provenance or {})
            state.diagnostics_status = 'complete'
            write_json(target / 'failure.json', failure_record('reconcile_convert_validate', error, state))
        except Exception as diagnostic_error:  # noqa: BLE001 -- preserve the original failure
            state.diagnostics_status = 'partial' if target is not None else 'unavailable'
            state.diagnostics_code = error_code(diagnostic_error)
            if target is not None:
                try:
                    write_json(target / 'failure.json', failure_record('reconcile_convert_validate', error, state))
                except Exception as rewrite_error:  # noqa: BLE001 -- safely record storage failure
                    state.diagnostics_code = error_code(rewrite_error)
        raise AnalysisError("reconcile_convert_validate", state.failure['error_type'],
                            publication=state.details()) from None


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
        state["stage"] = "java_source_dependencies"
        java_report = resolve_java(checkout_path, settings)
        state["stage"] = "image_scan"
        image, image_provenance = scan_image(image_reference, work / "image.syft.json", settings)
        state["provenance"]["image"] = image_provenance
        state["stage"] = "publication"
        return publish_catalogs(source, image, output, settings, assessor, state["provenance"], load_manifest(checkout_path), load_python_manifest(checkout_path), java_report)


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
        if repository_url is None:
            empty = work/'no-source'
            empty.mkdir()
            state['stage'] = 'source_scan'
            source = scan_source(empty, work/'source.syft.json', settings)
            state['stage'] = 'image_scan'
            image, image_provenance = scan_image(image_reference, work/'image.syft.json', settings)
            state['provenance'].update(image=image_provenance, source_kind='not-provided')
            state['stage'] = 'publication'
            return publish_catalogs(source, image, output, settings, assessor, state['provenance'])
        state["stage"] = "checkout"
        git_provenance = checkout(repository_url, commit, work / "checkout", settings)
        state["provenance"]["git"] = git_provenance
        state["stage"] = "source_scan"
        source = scan_source(work / "checkout", work / "source.syft.json", settings)
        state["stage"] = "java_source_dependencies"
        java_report = resolve_java(work / "checkout", settings)
        state["stage"] = "image_scan"
        image, image_provenance = scan_image(image_reference, work / "image.syft.json", settings)
        state["provenance"]["image"] = image_provenance
        state["stage"] = "publication"
        return publish_catalogs(source, image, output, settings, assessor, state["provenance"], load_manifest(work / "checkout"), load_python_manifest(work / "checkout"), java_report)

"""Checkpointed real-repository benchmark; failed stages never become PASS rows.

Build recipes run only here, never in the production scanning service. Images are
controlled source builds, not claims about upstream production deployments.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jsonschema.exceptions import ValidationError

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LANGUAGES = ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby")


def atomic_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for attempt in range(20):
        try:
            temporary.replace(path)
            break
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.025)


def run_command(args: list[str], log: Path, *, timeout: int = 600, cwd: Path | None = None, env: dict | None = None) -> str:
    log.parent.mkdir(parents=True, exist_ok=True)
    header = "Command: " + json.dumps(args) + "\n"
    timed_out = False
    with log.open("w", encoding="utf-8") as output:
        output.write(header)
        output.flush()
        process = subprocess.Popen(args, cwd=cwd or ROOT, env=env, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=os.name != "nt")
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False, timeout=15)
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
    stdout = log.read_text(encoding="utf-8", errors="replace")[len(header):]
    if timed_out:
        raise RuntimeError(f"timeout after {timeout}s; log={log.name}")
    if process.returncode:
        raise RuntimeError(f"exit={process.returncode}; log={log.name}; {stdout[-1200:].strip()}")
    return stdout.strip()


def recipe(row: dict) -> str:
    """Native builds in disposable build stages; no fake package metadata."""
    language = row["language"]
    if language == "Python":
        if row.get("build_system") == "plain":
            return """FROM python:3.12-slim-bookworm
WORKDIR /app
COPY src/src/ /app/src/
CMD ["python", "/app/src/app.py"]
"""
        extra_tools = "RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*\n" if row.get("id") == "python-attrs" else ""
        return """FROM python:3.12-slim-bookworm AS build
""" + extra_tools + """
WORKDIR /src
COPY src/ /src/
RUN pip install --no-cache-dir --prefix=/install /src
FROM python:3.12-slim-bookworm
COPY --from=build /install/ /usr/local/
CMD ["python", "--version"]
"""
    if language == "JavaScript":
        return """FROM node:22-bookworm-slim
WORKDIR /app
COPY src/ /app/
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund && rm -rf .git
CMD ["node", "--version"]
"""
    if language == "Ruby":
        # Git is used by gemspecs to enumerate files. Native extensions compile
        # only in the disposable build stage.
        return """FROM ruby:3.3-bookworm AS build
WORKDIR /src
COPY src/ /src/
RUN gem build *.gemspec && mkdir /packages && cp *.gem /packages/
RUN gem install --no-document /packages/*.gem
FROM ruby:3.3-slim-bookworm
COPY --from=build /usr/local/bundle/ /usr/local/bundle/
CMD ["ruby", "--version"]
"""
    if language == "Java":
        if row.get("build_system") == "gradle":
            return """FROM gradle:8.12-jdk17 AS build
WORKDIR /src
COPY src/ /src/
RUN gradle --no-daemon --max-workers=2 build -x test
FROM eclipse-temurin:17-jre-jammy
COPY --from=build /src/build/libs/ /app/lib/
CMD ["java", "-version"]
"""
        module = {"java-gson": "gson", "java-slf4j": "slf4j-api"}.get(row["id"])
        modules = " -pl " + module + " -am" if module else ""
        jars = r"RUN mkdir /jars && find . -path '*/target/*.jar' -type f ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*-tests.jar' ! -name 'original-*' -exec cp {} /jars/ \;"
        if module:
            # Only the selected library's actual built JAR and runtime dependencies
            # enter the image. Test/obfuscation artifacts stay in the build stage.
            jars = (
                f"RUN mkdir /jars && find /src/{module}/target -maxdepth 1 -type f -name '{module}-*.jar' "
                r"! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*test*.jar' ! -name '*obfus*.jar' -exec cp {} /jars/ \; "
                '&& test "$(find /jars -type f | wc -l)" = 1 '
                f"&& if [ -d /src/{module}/target/dependency ]; then find /src/{module}/target/dependency -maxdepth 1 -type f -name '*.jar' "
                r"-exec cp {} /jars/ \; ; fi"
            )
        # Gson's package lifecycle renames an obfuscation fixture class, so its
        # test sources must compile even though test execution is skipped.
        skip_test_compile = "false" if row["id"] == "java-gson" else "true"
        return """FROM maven:3.9-eclipse-temurin-17 AS build
ENV MAVEN_OPTS=-XX:ActiveProcessorCount=2
WORKDIR /src
COPY src/ /src/
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp""" + modules + " -DskipTests -Dmaven.test.skip=" + skip_test_compile + """ -Dcheckstyle.skip -Drat.skip=true -Dmaven.javadoc.skip=true -Dspotless.skip=true package dependency:copy-dependencies -DincludeScope=runtime
""" + jars + """
FROM eclipse-temurin:17-jre-jammy
COPY --from=build /jars/ /app/lib/
CMD ["java", "-version"]
"""
    if language == "Go":
        path = "./cmd/upterm" if row["id"] == "go-upterm" else "."
        return f"""FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY src/ /src/
ENV CGO_ENABLED=0
ENV GOMAXPROCS=2
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod git -c core.autocrlf=false reset --hard HEAD && if [ -f go.mod ]; then go build -buildvcs=true -o /out/app {path}; else GO111MODULE=off go build -o /out/app {path}; fi && go version -m /out/app > /out/go-build-info.txt
FROM debian:bookworm-slim
COPY --from=build /out/ /app/
CMD ["/app/app", "--help"]
"""
    if language == "Rust":
        # Auditable metadata is an explicit benchmark build option. An ordinary
        # stripped binary may reveal less; this is documented in coverage.
        return """FROM rust:1.85.1-bookworm AS build
ENV RUSTUP_TOOLCHAIN=1.85.1 CARGO_BUILD_JOBS=2
RUN cargo install cargo-auditable --version 0.6.6 --locked
WORKDIR /src
COPY src/ /src/
ENV CARGO_PROFILE_DEV_DEBUG=0
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo auditable build --locked --bins && mkdir /out && find target/debug -maxdepth 1 -type f -executable -exec cp {} /out/ \\; && test -n "$(ls -A /out)"
FROM debian:bookworm-slim
COPY --from=build /out/ /app/
CMD ["/bin/sh", "-c", "ls /app"]
"""
    raise ValueError(language)


def initial_result(row: dict) -> dict:
    return {**row, "status": "pending", "stage": None, "source_count": None, "image_count": None,
            "include": None, "exclude": None, "unknown": None, "final_count": None,
            "cyclonedx_valid": None, "seconds": 0.0, "image_id": None, "image_digest_kind": None,
            "fp": None, "fn": None, "accuracy_scope": "not independently fully labelled",
            "decision_mode": None, "bitbucket_tested": False, "error": None}


def render_reports(rows: list[dict], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    primary = len(rows) == 60 and Counter(row["language"] for row in rows) == {language: 10 for language in LANGUAGES}
    summary = {language: dict(Counter(row["status"] for row in rows if row["language"] == language)) for language in LANGUAGES}
    atomic_json(output / "results.json", {"schema_version": 1, "generated_at": datetime.now(UTC).isoformat(),
                "limitations": ["Public GitHub checkouts do not validate private Bitbucket authentication.",
                 "Controlled source-build images do not establish upstream production build linkage.",
                 "rules mode does not test LLM quality or the model contract.",
                 "Component presence is not code reachability.",
                 "Full inventory ground truth is not labelled; FP and FN remain null unless explicitly scoped."],
                "summary": summary, "repositories": rows})
    fields = ["id", "language", "repository_url", "commit", "image_id", "image_digest_kind", "image_config_digest", "source_count",
              "image_count", "include", "exclude", "unknown", "final_count", "os_count", "full_count", "inventory_scope", "fp", "fn", "accuracy_scope",
              "seconds", "cyclonedx_valid", "status", "stage", "decision_mode", "coverage", "expected_package", "expected_version",
              "expected_application_observed", "expected_application_in_final", "error"]
    with (output / "results.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    def cell(value: object) -> str:
        return "—" if value is None else str(value).replace("|", "\\|").replace("\n", " ")
    text = ["# Проверка 60 реальных репозиториев" if primary else "# Дополнительные Bitbucket fixtures", "",
            ("По 10 репозиториев для Java, JavaScript, Python, Rust, Go и Ruby." if primary else "Эти integration fixtures учитываются отдельно от основной матрицы 60 кодовых проектов.") + " Статус checkout/source_scanned/build_complete не означает завершённый тест системы.", "",
            "Образы собираются отдельным benchmark-процессом из закреплённых checkout. Это контролируемые сборки, а не образы production pipeline. GitHub не подтверждает доступ к Bitbucket. Режим rules не подтверждает качество LLM. FP/FN без независимой полной разметки не рассчитываются.", "",
            "Image ID в таблице сокращён; полное значение и его тип сохранены в CSV/JSON. INCLUDE/UNKNOWN считают идентичности, а Source/Image/Final — записи пакетов: дубликаты расположений могут давать разные числа. `partial` означает наличие UNKNOWN. Bitbucket fixture без объявленных runtime-зависимостей проверяет доступ и корректность потока, но не полноту поиска реальных зависимостей приложения.", "",
            "`App image/final` проверяет одну закреплённую release-идентичность основного пакета по точному PURL name/version/ecosystem. Это отдельная ограниченная проверка, не FP/FN всех зависимостей; `false` может означать, что локальная сборка не сохранила release version. `—` означает, что точная ожидаемая идентичность неприменима.", "",
            "`Сек.` — накопленное время зафиксированных попыток этого репозитория: checkout, source scan, сборки, анализ, повторное чтение cache и replay; записанные неуспешные попытки также включены. Прерванные до checkpoint этапы могут не войти в сумму. Это не измерение производительности production API или LLM. Длительность последнего нового вызова сервиса отдельно записана как `last_analysis_seconds` в JSON.", "",
            "| Язык | Завершено | Ошибка | Прочее |", "|---|---:|---:|---:|"]
    for language in LANGUAGES:
        counts = summary[language]
        complete = counts.get("completed_rules", 0) + counts.get("completed_llm", 0)
        failed = counts.get("failed", 0)
        total = sum(1 for row in rows if row["language"] == language)
        text.append(f"| {language} | {complete} | {failed} | {total-complete-failed} |")
    text += ["", "| Репозиторий | Язык | Commit | Image ID | Source | Image | INCLUDE / EXCLUDE / UNKNOWN | Final | App image/final | CDX | Сек. | Режим | Coverage | Статус |",
             "|---|---|---|---|---:|---:|---|---:|---|---|---:|---|---|---|"]
    for row in rows:
        name = row["repository_url"].removesuffix(".git").split("/", 3)[-1]
        coverage = row.get("coverage", "not measured")
        if row.get("fixture_kind"):
            coverage += "; fixture without declared runtime deps"
        if row["id"] in {"bitbucket-java-maven-api", "bitbucket-java-maven-orders", "bitbucket-java-gradle-worker", "bitbucket-java-gradle-billing", "bitbucket-npm-frontend", "bitbucket-npm-admin"}:
            coverage += "; no application source code"
        if row["language"] == "Rust":
            coverage += "; auditable build"
        if row["id"] == "go-assetfinder":
            coverage += "; GOPATH build without module identity"
        elif row["language"] == "Go":
            coverage += "; local main module may report (devel)"
        text.append("| " + " | ".join(map(cell, [f"[{name}]({row['repository_url'].removesuffix('.git')})", row["language"], (row["commit"] or "")[:12], (row.get("image_id") or "")[:19] or None, row["source_count"], row["image_count"],
                    "/".join(cell(row[key]) for key in ("include", "exclude", "unknown")), row["final_count"], cell(row.get("expected_application_observed")) + "/" + cell(row.get("expected_application_in_final")), row["cyclonedx_valid"], round(row["seconds"], 1), row["decision_mode"], coverage, row["status"]])) + " |")
    errors = [row for row in rows if row.get("error")]
    if errors:
        text += ["", "## Незавершённые этапы", ""]
        text += [f"- `{row['id']}` ({row['stage']}): {cell(row['error'])}" for row in errors]
    (output / "results.md").write_text("\n".join(text) + "\n", encoding="utf-8")


def checkout(row: dict, case: Path, timeout: int) -> Path:
    source = case / "src"
    environment = None
    if row.get("source_host") == "bitbucket.org":
        from inspect_bitbucket import credentials
        secret = credentials(Path(os.environ.get("SBOM_BENCHMARK_CREDENTIAL_FILE", r"G:\code\artifact_graph\.env")))
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("GIT_CONFIG", "GIT_TRACE", "GIT_CURL"))}
        token = base64.b64encode(("x-bitbucket-api-token-auth:" + secret["BITBUCKET_TOKEN"]).encode()).decode()
        environment.update(GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="http.https://bitbucket.org/.extraHeader",
                           GIT_CONFIG_VALUE_0="Authorization: Basic " + token,
                           GIT_CONFIG_KEY_1="credential.helper", GIT_CONFIG_VALUE_1="", GIT_TERMINAL_PROMPT="0")
    if not row.get("commit"):
        raise RuntimeError("Release tag was not resolved to a commit")
    if not (source / ".git").is_dir():
        run_command(["git", "clone", "--depth", "1", "--single-branch", "--branch", row["release_ref"],
                     row["repository_url"], str(source)], case / "clone.log", timeout=timeout, env=environment)
    try:
        run_command(["git", "-C", str(source), "cat-file", "-e", row["commit"] + "^{commit}"], case / "object-check.log", timeout=60, env=environment)
    except RuntimeError:
        # An interrupted shallow clone may already have .git but not its objects.
        run_command(["git", "-C", str(source), "fetch", "--depth", "1", "origin", row["commit"]], case / "resume-fetch.log", timeout=timeout, env=environment)
    run_command(["git", "-C", str(source), "checkout", "--detach", row["commit"]], case / "checkout.log", timeout=60, env=environment)
    actual = run_command(["git", "-C", str(source), "rev-parse", "HEAD"], case / "head.log", timeout=60, env=environment)
    if actual != row["commit"]:
        raise RuntimeError("Checkout HEAD mismatch")
    modified = run_command(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"], case / "worktree-status.log", timeout=60, env=environment)
    if modified:
        raise RuntimeError("Benchmark checkout contains local changes; preserving them and refusing to build")
    row["bitbucket_tested"] = row.get("source_host") == "bitbucket.org"
    return source


def source_scan(row: dict, case: Path, source: Path, syft: Path) -> None:
    config = case / "syft.yaml"
    config.write_text("check-for-app-update: false\njava:\n  use-network: false\n", encoding="utf-8")
    target = case / "source.syft.json"
    if not target.exists():
        run_command([str(syft), "scan", "dir:" + str(source), "--config", str(config),
                     "-o", "syft-json=" + str(target)], case / "source-scan.log", timeout=600, cwd=case)
    document = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(document.get("artifacts"), list):
        raise TypeError("Source scan did not produce a Syft artifacts array")
    row["source_count"] = len(document["artifacts"])
    row["source_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()


def build_image(row: dict, case: Path, timeout: int) -> None:
    dockerfile = case / "Dockerfile.benchmark"
    dockerfile.write_text(recipe(row), encoding="utf-8")
    (case / ".dockerignore").write_text("*\n!src/\n!src/**\n!Dockerfile.benchmark\n", encoding="utf-8")
    tag = "sbom-creator-benchmark/" + row["id"] + ":" + row["commit"][:12]
    run_command(["docker", "build", "--progress", "plain", "--label", "org.opencontainers.image.revision=" + row["commit"],
                 "--label", "sbom-creator.benchmark=controlled-source-build", "-t", tag, "-f", str(dockerfile), str(case)],
                case / "build.log", timeout=timeout)
    image_id = run_command(["docker", "image", "inspect", tag, "--format", "{{.Id}}"], case / "image-inspect.log", timeout=60)
    row.update(image_id=image_id, image_reference="docker.io/" + tag, image_digest_kind="immutable local Docker image ID (OCI index or config)",
               build_recipe_sha256=hashlib.sha256(dockerfile.read_bytes()).hexdigest())



def export_fixture(row, case, timeout):
    run_command(["docker", "image", "save", "-o", str(case / "fixture.tar"), row["image_id"]],
                case / "archive.log", timeout=timeout)
    with tarfile.open(case / "fixture.tar") as saved:
        manifests = json.load(saved.extractfile("manifest.json"))
        assert len(manifests) == 1
        config_bytes = saved.extractfile(manifests[0]["Config"]).read(8 * 1024 * 1024 + 1)
        assert len(config_bytes) <= 8 * 1024 * 1024
        row["image_config_digest"] = "sha256:" + hashlib.sha256(config_bytes).hexdigest()


def analyze(row: dict, case: Path, mode: str, timeout: int, *, fresh: bool = False) -> None:
    if not row.get("image_id"):
        raise RuntimeError("No completed native image build")
    cached = Path(row["analysis_directory"]) if not fresh and row.get("analysis_directory") and row.get("decision_mode") == mode else None
    if cached and (cached / "summary.json").exists():
        try:
            if not row.get("final_sha256"):
                raise RuntimeError("Cached result has no recorded final fingerprint")
            read_analysis(row, cached, mode, expected_final_sha=row["final_sha256"])
            from sbom_creator.core import POLICY_VERSION, RULES_POLICY_VERSION
            if row.get("policy_version") != (RULES_POLICY_VERSION if mode == "rules" else POLICY_VERSION):
                raise RuntimeError("Cached assessment uses an older policy; replay or rescan is required")
            if row.get("inventory_scope") != "non-os-packages-v1":
                raise RuntimeError("Cached export uses the legacy full inventory scope; replay or rescan is required")
            return
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, ValidationError) as error:
            row["cache_rejected"] = {"directory": str(cached), "error_type": type(error).__name__}
            cached = None
    destination = cached if cached and (cached / "summary.json").exists() else case / ("analysis-" + mode + "-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f"))
    row["analysis_directory"] = str(destination)
    environment = dict(os.environ)
    environment.update(SBOM_SYFT_BINARY=str(ROOT / ".tools" / "syft" / "syft.exe"), SBOM_IMAGE_ARCHIVE=str((case / "fixture.tar").resolve()), SBOM_REGISTRY_HOSTS="docker.io")
    command = [sys.executable, "-m", "sbom_creator.cli"]
    if row.get("source_host") == "bitbucket.org":
        from inspect_bitbucket import credentials
        secret = credentials(Path(os.environ.get("SBOM_BENCHMARK_CREDENTIAL_FILE", r"G:\code\artifact_graph\.env")))
        environment.update(SBOM_BITBUCKET_HOSTS="bitbucket.org", SBOM_BITBUCKET_AUTH_MODE="basic",
                           SBOM_BITBUCKET_TOKEN=secret["BITBUCKET_TOKEN"], SBOM_BITBUCKET_USERNAME="x-bitbucket-api-token-auth")
        command += ["analyze", "--repository-url", row["repository_url"], "--commit", row["commit"]]
    else:
        command += ["analyze-local", "--source", str(case / "src")]
    if not (destination / "summary.json").exists():
        export_fixture(row, case, timeout)
        service_started = time.monotonic()
        run_command(command + ["--image", "docker.io/" + row["image_reference"].removeprefix("docker.io/"), "--output", str(destination), "--mode", mode], case / "analyze.log", timeout=timeout, env=environment)
        row["last_analysis_seconds"] = round(time.monotonic() - service_started, 3)
    read_analysis(row, destination, mode)


def read_analysis(row: dict, destination: Path, mode: str, *, expected_final_sha: str | None = None) -> None:
    from sbom_creator.validation import validate_cyclonedx, validate_export_identity, validate_syft
    final_path = destination / "final.cdx.json"
    if not final_path.exists():
        raise RuntimeError("Service returned without final.cdx.json")
    final_sha = hashlib.sha256(final_path.read_bytes()).hexdigest()
    if expected_final_sha is not None and final_sha != expected_final_sha:
        raise RuntimeError("Cached final SBOM fingerprint changed")
    summary = json.loads((destination / "summary.json").read_text(encoding="utf-8"))
    if summary.get("cyclonedx_valid") is not True or summary.get("status") != "succeeded":
        raise RuntimeError("Pipeline did not confirm validation and successful publication")
    final = json.loads(final_path.read_text(encoding="utf-8"))
    source = json.loads((destination / "source.syft.json").read_text(encoding="utf-8"))
    image = json.loads((destination / "image.syft.json").read_text(encoding="utf-8"))
    selected = json.loads((destination / "selected.syft.json").read_text(encoding="utf-8"))
    coverage = json.loads((destination / "coverage.json").read_text(encoding="utf-8"))
    validate_syft(source)
    validate_syft(image)
    validate_syft(selected)
    validate_cyclonedx(final)
    provenance = json.loads((destination / "provenance.json").read_text(encoding="utf-8"))
    image_provenance = provenance.get("image", {})
    if image_provenance.get("acquisition_method") == "syft-direct-v1":
        if not row.get("image_config_digest") or image_provenance.get("image_config_digest") != row["image_config_digest"]:
            raise RuntimeError("Published image config differs from exported benchmark build")
    elif image_provenance.get("image_id") != row["image_id"]:
        raise RuntimeError("Published image ID differs from benchmark build")
    config_digest = provenance.get("image", {}).get("image_config_digest")
    if not config_digest or config_digest != image.get("source", {}).get("metadata", {}).get("imageID"):
        raise RuntimeError("Published image config digest differs from scanned image")
    if provenance.get("git", {}).get("commit") != row.get("commit"):
        raise RuntimeError("Published Git commit differs from benchmark manifest")
    if provenance.get("mode") != mode or provenance.get("assessment", {}).get("mode") != mode:
        raise RuntimeError("Published assessment mode differs from requested mode")
    for name in ("source.syft.json", "image.syft.json"):
        if provenance.get("input_hashes", {}).get(name) != hashlib.sha256((destination / name).read_bytes()).hexdigest():
            raise RuntimeError("Published source/image fingerprint differs from saved bytes")
    decisions = json.loads((destination / "decisions.json").read_text(encoding="utf-8"))
    if isinstance(decisions, dict):
        decisions = decisions.get("decisions", decisions.get("items", []))
    counts = Counter(str(item.get("decision", item.get("status", ""))).upper() for item in decisions)
    if (coverage.get("mode") != mode or summary.get("decisions") != dict(counts)
            or coverage.get("decisions") != {key: counts[key] for key in ("INCLUDE", "EXCLUDE", "UNKNOWN")}):
        raise RuntimeError("Decision counts or coverage mode differ from published summary")
    if (summary.get("partial") != coverage.get("partial_inventory")
            or (counts["UNKNOWN"] or coverage.get("source_checkout_incomplete")) and summary.get("partial") is not True):
        raise RuntimeError("Published partial status differs from observed coverage")
    selected_by_id = {artifact["id"]: artifact for artifact in selected["artifacts"]}
    image_by_id = {artifact["id"]: artifact for artifact in image["artifacts"]}
    included_ids = {artifact_id for decision in decisions if decision.get("decision") == "INCLUDE" for artifact_id in decision.get("selected_image_artifact_ids", decision.get("image_artifact_ids", []))}
    if set(selected_by_id) != included_ids or any(value != image_by_id.get(key) for key, value in selected_by_id.items()):
        raise RuntimeError("Selected artifacts differ from positively included image evidence")
    if summary.get("inventory_scope") == "non-os-packages-v1":
        from sbom_creator.exporter import validate_inventory_views
        full = json.loads((destination / "full.cdx.json").read_bytes())
        os_packages = json.loads((destination / "os.cdx.json").read_bytes())
        validate_inventory_views(full, final, os_packages, selected)
        if summary.get("os_count") != len(os_packages["components"]) or summary.get("full_count") != len(full["components"]):
            raise RuntimeError("Inventory scope counts differ from exported views")
    elif "inventory_scope" in summary:
        raise RuntimeError("Unsupported inventory scope")
    else:
        validate_export_identity(final, selected)
    if (summary.get("source_count") != len(source["artifacts"]) or summary.get("image_count") != len(image["artifacts"])
            or summary.get("selected_count") != len(selected["artifacts"])
            or summary.get("final_count") != len(final.get("components", []))):
        raise RuntimeError("Published summary counts differ from actual documents")
    row.update(source_count=len(source["artifacts"]), image_count=len(image["artifacts"]),
               include=counts["INCLUDE"], exclude=counts["EXCLUDE"], unknown=counts["UNKNOWN"],
               final_count=len(final.get("components", [])), cyclonedx_valid=True, decision_mode=mode,
               policy_version=coverage.get("policy_version"),
               inventory_scope=summary.get("inventory_scope", "legacy-full-inventory"),
               os_count=summary.get("os_count"), full_count=summary.get("full_count", len(final.get("components", []))),
               coverage="partial" if summary.get("partial") else "no unresolved candidates observed",
               image_digest_kind="immutable local Docker image ID (OCI index or config)", image_config_digest=config_digest,
               expected_application_observed=expected_observed(row, image["artifacts"]),
               expected_application_in_final=expected_observed(row, final.get("components", [])),
               status="completed_" + mode, final_sha256=final_sha)


def expected_observed(row: dict, components: list[dict]) -> bool | None:
    """One release identity from the manifest; deliberately not full inventory truth."""
    from packageurl import PackageURL
    package, version = row.get("expected_package"), row.get("expected_version")
    if row.get("id") in {"bitbucket-java-maven-api", "bitbucket-java-maven-orders", "bitbucket-npm-frontend", "bitbucket-npm-admin"}:
        return None  # These existing fixtures contain manifests/CI scripts, not application source.
    if not package or not version or version == "unspecified":
        return None
    ecosystem = {"Java": "maven", "JavaScript": "npm", "Python": "pypi", "Rust": "cargo", "Go": "golang", "Ruby": "gem"}[row["language"]]
    wanted = package.replace(":", "/") if ecosystem == "maven" else package
    if ecosystem == "pypi":
        wanted = re.sub(r"[-_.]+", "-", wanted).lower()
    for component in components:
        try:
            purl = PackageURL.from_string(component.get("purl", ""))
        except (ValueError, TypeError):
            continue
        name = "/".join(part for part in (purl.namespace, purl.name) if part)
        if ecosystem == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
        if purl.type == ecosystem and name == wanted and purl.version == version:
            return True
    return False


def replay(row: dict, case: Path, mode: str) -> None:
    """Reconcile preserved real scans after code changes, retaining prior evidence."""
    from sbom_creator.acquire import Settings
    from sbom_creator.pipeline import assessor_for, publish_catalogs
    original = Path(row.get("analysis_directory", str(case / "analysis")))
    if not (original / "image.syft.json").exists():
        original = original.with_name(original.name + ".diagnostics")
    source = json.loads((original / "source.syft.json").read_text(encoding="utf-8"))
    image = json.loads((original / "image.syft.json").read_text(encoding="utf-8"))
    provenance_path = original / "provenance.json"
    if not provenance_path.exists():
        raise RuntimeError("Preserved scans have no provenance; a fresh analysis is required")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["replay_of"] = str(original)
    provenance["mode"] = mode
    destination = case / ("replay-" + mode + "-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f"))
    row["analysis_directory"] = str(destination)
    publish_catalogs(source, image, destination, Settings(syft_binary=str(ROOT / ".tools" / "syft" / "syft.exe")), assessor_for(mode), provenance)
    read_analysis(row, destination, mode)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "results" / "run-20260929")
    parser.add_argument("--manifest", type=Path, default=HERE / "manifest.json")
    parser.add_argument("--work", type=Path, default=HERE / ".work")
    parser.add_argument("--phase", choices=("checkout", "source", "build", "analyze", "replay", "all"), default="all")
    parser.add_argument("--language", choices=LANGUAGES, action="append")
    parser.add_argument("--id", action="append")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--build-timeout", type=int, default=600)
    parser.add_argument("--mode", choices=("rules", "llm"), default="rules")
    parser.add_argument("--fresh", action="store_true", help="Rescan instead of reusing a successful analysis; preserve prior output")
    parser.add_argument("--syft", type=Path, default=ROOT / ".tools" / "syft" / "syft.exe")
    args = parser.parse_args()
    args.output, args.work, args.syft = args.output.resolve(), args.work.resolve(), args.syft.resolve()
    rows = [initial_result(row) for row in json.loads(args.manifest.read_text(encoding="utf-8"))["repositories"]]
    previous = args.output / "results.json"
    if previous.exists():
        by_id = {row["id"]: row for row in json.loads(previous.read_text(encoding="utf-8"))["repositories"]}
        rows = [by_id.get(row["id"], row) for row in rows]
    selected = [row for row in rows if (not args.language or row["language"] in args.language) and (not args.id or row["id"] in args.id)]
    if args.limit:
        selected = selected[:args.limit]
    if args.language:
        selected.sort(key=lambda row: args.language.index(row["language"]))
    render_reports(rows, args.output)
    for row in selected:
        case = args.work / row["id"]
        case.mkdir(parents=True, exist_ok=True)
        start = time.monotonic()
        attempt_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
        attempt_dir = case / "attempts" / attempt_id
        attempt_dir.mkdir(parents=True, exist_ok=True)
        for previous_log in case.glob("*.log"):
            shutil.copy2(previous_log, attempt_dir / ("previous-" + previous_log.name))
        if "attempts" not in row and row["status"] != "pending":
            row["attempts"] = [{"kind": "legacy_checkpoint", "status": row["status"], "stage": row["stage"], "error": row["error"]}]
        row["error"] = None
        try:
            if args.phase in {"checkout", "source", "build", "all"}:
                row["stage"] = "checkout"
                source = checkout(row, case, timeout=180)
                row["status"] = "checkout_complete"
            if args.phase in {"source", "build", "all"}:
                row["stage"] = "source_scan"
                source_scan(row, case, source, args.syft)
                row["status"] = "source_scanned"
            if args.phase in {"build", "all"}:
                row["stage"] = "native_image_build"
                build_image(row, case, args.build_timeout)
                row["status"] = "build_complete"
            if args.phase in {"analyze", "all"}:
                row["stage"] = "analyze"
                analyze(row, case, args.mode, timeout=1200, fresh=args.fresh)
            if args.phase == "replay":
                row["stage"] = "reconcile_replay"
                replay(row, case, args.mode)
            row["stage"] = "complete" if row["status"].startswith("completed_") else row["stage"]
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, ValidationError) as error:
            row["status"], row["error"] = "failed", str(error)[-2000:]
        row["seconds"] += time.monotonic() - start
        row.setdefault("attempts", []).append({"id": attempt_id, "phase": args.phase, "status": row["status"], "stage": row["stage"],
                                               "error": row["error"], "seconds": round(time.monotonic()-start, 3),
                                               "analysis_directory": row.get("analysis_directory"), "image_id": row.get("image_id"),
                                               "source_count": row.get("source_count"), "image_count": row.get("image_count"), "final_count": row.get("final_count")})
        for current_log in case.glob("*.log"):
            shutil.copy2(current_log, attempt_dir / current_log.name)
        atomic_json(case / "result.json", row)
        render_reports(rows, args.output)
        print(row["id"], row["status"], "source=", row["source_count"], "image=", row["image_count"], "final=", row["final_count"], flush=True)
    print(json.dumps({language: dict(Counter(row["status"] for row in rows if row["language"] == language)) for language in LANGUAGES}), flush=True)


if __name__ == "__main__":
    main()

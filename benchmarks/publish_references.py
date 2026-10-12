"""Validate and publish compact immutable build references, without build binaries."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import Counter
from datetime import UTC, datetime

from build_references import OUT, ROOT, WORK, inspect_bom
from run import atomic_json

DEST = ROOT / "benchmarks/references/build-v1"


def main():
    manifest = json.loads((ROOT / "benchmarks/manifest.json").read_text("utf-8"))["repositories"]
    rows = []
    for project in manifest:
        path = OUT / project["id"] / "result.json"
        result = json.loads(path.read_text("utf-8")) if path.exists() else {"status": "pending"}
        row = {"id": project["id"], "language": project["language"], "commit": project["commit"],
               "repository_url": project["repository_url"],
               "build_status": result["status"], "old_image_pair_verified": False,
               "direct_accuracy_measured": False}
        rows.append(row)
        if result["status"] != "generated":
            row["error"] = result.get("error")
            continue
        if result["commit"] != project["commit"]:
            raise ValueError("manifest commit changed")
        target = DEST / project["id"]
        target.mkdir(parents=True, exist_ok=True)
        boms = []
        for recorded in result["boms"]:
            source = ROOT / recorded["path"]
            measured = inspect_bom(source)
            if measured["sha256"] != recorded["sha256"]:
                raise ValueError(f"reference changed: {source}")
            boms.append((source, measured))
        # The original image recipe selects one module for these two reactors.
        module = {"java-gson": "gson", "java-slf4j": "slf4j-api"}.get(project["id"])
        candidates = [b for b in boms if f"/{module}/target/" in b[0].as_posix()] if module else boms
        if not candidates:
            raise ValueError(f"selected module reference absent: {project['id']}")
        main_bom = min(candidates, key=lambda b: len(b[0].parts))
        shutil.copyfile(main_bom[0], target / "sbom.json")
        selected = inspect_bom(target / "sbom.json")
        modules = []
        for i, (source, info) in enumerate(boms):
            if source == main_bom[0]:
                continue
            module_path = target / "modules" / str(i) / "sbom.json"
            module_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, module_path)
            modules.append(inspect_bom(module_path))
        recipe = OUT / project["id"] / "Dockerfile"
        text = recipe.read_text("utf-8")
        if hashlib.sha256(text.encode()).hexdigest() != result["recipe_sha256"]:
            raise ValueError("recipe hash mismatch")
        shutil.copyfile(recipe, target / "Dockerfile")
        for name, digest in result.get("recipe_inputs", {}).items():
            source = WORK / project["id"] / name
            if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
                raise ValueError("recipe input changed")
            shutil.copyfile(source, target / name)
        log = WORK / project["id"] / "build.log"
        log_bytes = log.read_bytes()
        bases = sorted(set(re.findall(r"(?:docker.io/)?library/[^\s]+@sha256:[0-9a-f]{64}", log_bytes.decode(errors="replace"))))
        artifact_root = main_bom[0]
        while artifact_root.parent != OUT / project["id"]:
            artifact_root = artifact_root.parent
        native = artifact_root / "native-graph.json"
        evidence = []
        for name in ("native-graph.json", "Gemfile", "Gemfile.lock", "go-build-info.txt", "root.pyproject.toml"):
            source = artifact_root / name
            if source.exists():
                shutil.copyfile(source, target / name)
                evidence.append({"file": name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
        graph_ready = selected["root_graph_present"]
        direct_count = selected["direct_edges"]
        graph_source = "CycloneDX plugin" if graph_ready else None
        if native.exists():
            data = json.loads(native.read_text("utf-8"))
            bom_data = json.loads((target / "sbom.json").read_text("utf-8"))
            inventory = {c.get("purl") for c in bom_data.get("components", [])}
            native_refs = {edge["ref"] for edge in data["dependencies"]}
            if len(native_refs) != len(data["dependencies"]) or not native_refs <= inventory:
                raise ValueError("native graph duplicate or component absent from plugin SBOM")
            if any(not set(edge["dependsOn"]) <= native_refs for edge in data["dependencies"]):
                raise ValueError("dangling native graph dependency")
            root_edges = [d for d in data["dependencies"] if d["ref"] == data["root"]]
            if len(root_edges) != 1:
                raise ValueError("native graph root missing or ambiguous")
            graph_ready, direct_count, graph_source = True, len(root_edges[0]["dependsOn"]), "Bundler + built gemspec sidecar"
        notes = []
        if project["language"] == "Java":
            notes.append("Compile/runtime/provided/system scopes; tests excluded. Provided is not proof of image presence.")
        if project["language"] == "JavaScript":
            notes.append("Production install/pack; explicit build for axios/lodash; dev dependencies excluded from reference.")
        if project["language"] == "Python":
            notes.append("Built and installed in separate project venv; generator isolated. Environment SBOM may include bootstrap pip, outside project root graph.")
        if project["language"] == "Rust":
            notes.append("Default features, Linux amd64, cargo auditable debug bins; workspace module SBOMs retained.")
        if project["language"] == "Ruby":
            notes.append("Plugin emits no dependency graph. Native sidecar derives runtime edges independently from built gemspec and Bundler; wrapper Gemfile excludes development tools.")
            notes.append("Plugin component metadata/hashes come from RubyGems API; they are not hashes of the locally rebuilt gem.")
        if project["id"] == "go-assetfinder":
            notes.append("Benchmark-only go mod init after successful original GOPATH build; no third-party modules added.")
        if project.get("build_system") == "plain":
            notes.append("Benchmark packaging overlay: original plain Python fixture has no build metadata. Added lab-python 0.0.0+benchmark wheel packaging with empty dependencies; code unchanged. Not an upstream-authored dependency declaration.")
            row["benchmark_packaging_overlay"] = True
        if project["id"] == "python-python-certifi":
            notes.append("setup.py project: generator root pyproject is derived from installed wheel METADATA, not handwritten dependencies.")
        row.update(sbom=selected["path"], schema_valid=True, components=selected["components"],
                   direct_graph_ready=graph_ready, direct_edges=direct_count, graph_source=graph_source,
                   generator_version=result["generator_version"], notes=notes)
        atomic_json(target / "provenance.json", {**row, "reference": selected, "module_references": modules,
                    "recipe_sha256": result["recipe_sha256"], "build_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
                    "recipe_inputs": result.get("recipe_inputs", {}),
                    "local_build_log": log.relative_to(ROOT).as_posix(), "resolved_builder_images": bases,
                    "native_evidence": evidence, "build_started_at": result["started_at"],
                    "build_finished_at": result["finished_at"]})
    summary = {"schema_version": 1, "generated_at": datetime.now(UTC).isoformat(), "projects": rows,
               "counts": dict(Counter(r["build_status"] for r in rows)),
               "direct_graph_ready": sum(r.get("direct_graph_ready", False) for r in rows),
               "direct_root_edges": sum(r.get("direct_edges") or 0 for r in rows),
               "zero_direct_dependency_roots": sum(r.get("direct_edges") == 0 for r in rows),
               "paired_with_old_images": 0}
    atomic_json(DEST / "index.json", summary)
    lines = ["# Сборочные эталоны CycloneDX — B0", "", "Эталоны получены независимо от Syft и правил сервиса, из закреплённых коммитов.",
             "Повторные сборки не доказывают совпадение разрешённых версий со старыми образами B0. Точность B0 пока не пересчитана.", "",
             "| Язык | Проектов | SBOM получен | Есть граф для прямых зависимостей |", "|---|---:|---:|---:|"]
    for language in ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby"):
        subset = [r for r in rows if r["language"] == language]
        lines.append(f"| {language} | {len(subset)} | {sum(r['build_status'] == 'generated' for r in subset)} | {sum(r.get('direct_graph_ready', False) for r in subset)} |")
    lines += ["", "Граф Ruby — отдельное свидетельство Bundler/gemspec; сам плагин граф не формирует. Для lab-python без метаданных добавлена тестовая упаковка wheel: это отдельный случай с benchmark overlay, а не исходная декларация автора.",
              f"Всего {summary['direct_root_edges']} прямых рёбер выбранных корней; у {summary['zero_direct_dependency_roots']} проектов их ноль. Такие случаи нельзя превращать в 100% precision/recall или использовать для искусственного завышения средней точности.",
              "Количество прямых рёбер относится к корню выбранного проекта/модуля и указанному профилю сборки, а не к исполнению кода в runtime.", "",
              "| Проект | Сборка | Компонентов, включая корень | Прямых рёбер | Источник графа |", "|---|---|---:|---:|---|"]
    for row in rows:
        link = f"[{row['id']}](../benchmarks/references/build-v1/{row['id']}/sbom.json)" if row.get("sbom") else row["id"]
        lines.append(f"| {link} | {row['build_status']} | {row.get('components', '—')} | {row.get('direct_edges') if row.get('direct_edges') is not None else '—'} | {row.get('graph_source') or '—'} |")
    lines += ["", "Повтор: `python benchmarks/build_references.py`, затем `python benchmarks/publish_references.py`. `--id <id> --retry` повторяет отдельный проект.",
              "Полные логи и resolver dumps остаются локально; в Git сохранены SBOM, рецепты, хеши, версии генераторов и компактные native-свидетельства.",
              "Рецепты используют плавающие теги builder-образов; фактически разрешённые digest сохранены в provenance.json. Новая сборка не обещает побайтовое совпадение без закрепления всего окружения и разрешённых зависимостей.",
              "", "## Генераторы", "",
              "- [CycloneDX Maven](https://github.com/CycloneDX/cyclonedx-maven-plugin): 2.9.3, aggregate BOM и отдельные BOM выбранных модулей.",
              "- [CycloneDX npm](https://github.com/CycloneDX/cyclonedx-node-npm): 6.0.1, production dependency tree.",
              "- [CycloneDX Python](https://github.com/CycloneDX/cyclonedx-python): 7.5.0, environment установленного проекта с отдельным окружением генератора.",
              "- [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo): 0.5.9, CycloneDX 1.5, те же default features и Linux target.",
              "- [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod): 1.12.0, app с тем же main и CGO_ENABLED=0.",
              "- [CycloneDX Ruby, закреплённый commit](https://github.com/CycloneDX/cyclonedx-ruby-gem/tree/7efedd6422cc32d9bdefbb6eddb7b4eaa3857309): JSON; это git-версия, не опубликованный gem 1.1.0."]
    (ROOT / "docs/build-references-v1.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "projects"}, ensure_ascii=False))


if __name__ == "__main__":
    main()

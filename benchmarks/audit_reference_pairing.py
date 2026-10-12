"""Read-only R1/B0 compatibility diagnostic. Never computes direct accuracy."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from packageurl import PackageURL

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ROOT / "benchmarks/references/build-v1"


def read(path, expected=None):
    raw = path.read_bytes()
    if expected and hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"Evidence hash mismatch: {path}")
    return json.loads(raw)


def coordinate(purl):
    """Diagnostic coordinate only: qualifiers/subpath are NOT identity proof."""
    if not purl:
        return None
    value = PackageURL.from_string(purl)
    name = re.sub(r"[-_.]+", "-", value.name).lower() if value.type == "pypi" else value.name
    return value.type, value.namespace or "", name, value.version or ""


def components(document):
    def walk(items):
        for item in items:
            yield item
            yield from walk(item.get("components", []))
    return list(walk(document.get("components", []))) + list(walk(
        [document["metadata"]["component"]] if document.get("metadata", {}).get("component") else []))


def observation(key, observed):
    if key is None or not key[3]:
        return {"state": "reference_coordinate_unresolved"}
    matches = [p for p, candidate in observed if candidate == key]
    if matches:
        return {"state": "same_coordinate", "purls": sorted(set(matches))}
    other = [p for p, candidate in observed if candidate and candidate[:3] == key[:3]]
    if other:
        return {"state": "other_version_only", "purls": sorted(set(other))}
    return {"state": "not_observed"}


def direct_edges(provenance, document, directory):
    if provenance["graph_source"] == "Bundler + built gemspec sidecar":
        receipt = next(e for e in provenance["native_evidence"] if e["file"] == "native-graph.json")
        native = read(directory / "native-graph.json", receipt["sha256"])
        edge = next(e for e in native["dependencies"] if e["ref"] == native["root"])
        return [(p, p) for p in edge["dependsOn"]]
    root = document["metadata"]["component"]["bom-ref"]
    edges = [e for e in document.get("dependencies", []) if e["ref"] == root]
    if len(edges) != 1:
        raise ValueError("Missing or ambiguous reference root graph")
    by_ref = {c["bom-ref"]: c for c in components(document) if "bom-ref" in c}
    return [(ref, by_ref[ref].get("purl")) for ref in edges[0].get("dependsOn", [])]


def declaration_evidence(project, key):
    """Read exact Git blobs, never infer scope from a library's name."""
    if key is None or project["language"] not in {"Java", "Rust"}:
        return None
    module = {"java-gson": "gson/", "java-slf4j": "slf4j-api/"}.get(project["id"], "")
    filename = module + "pom.xml" if project["language"] == "Java" else "Cargo.toml"
    checkout = ROOT / "benchmarks/.work/build-references-v1" / project["id"] / "src"
    raw = subprocess.check_output(["git", "show", project["commit"] + ":" + filename], cwd=checkout)
    declarations = []
    if project["language"] == "Rust":
        data = tomllib.loads(raw.decode("utf-8"))
        for target, sections in [(None, data), *list(data.get("target", {}).items())]:
            for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
                for alias, value in sections.get(kind, {}).items():
                    name = value.get("package", alias) if isinstance(value, dict) else alias
                    if name == key[2]:
                        declarations.append({"kind": kind, "target": target, "alias": alias, "value": value})
    else:
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        for dep in ET.fromstring(raw).findall("m:dependencies/m:dependency", ns):
            values = {c.tag.split("}")[-1]: c.text for c in dep}
            if (values.get("groupId"), values.get("artifactId")) == key[1:3]:
                declarations.append(values)
    return {"file": filename, "git_blob_sha256": hashlib.sha256(raw).hexdigest(),
            "scope": "literal declarations only; inherited/profile/effective graph not resolved",
            "declarations": declarations}


def audit():
    baseline = read(ROOT / "docs/verification-direct-syft-60.json")
    manifest = {r["id"]: r for r in read(ROOT / "benchmarks/manifest.json")["repositories"]}
    rows = []
    totals = Counter()
    for old in baseline["rows"]:
        directory = Path(old["analysis_directory"])
        provenance = read(directory / "provenance.json")
        final = read(directory / "final.cdx.json", old["final_sha256"])
        inventories = {kind: read(directory / f"{kind}.syft.json", provenance["input_hashes"][f"{kind}.syft.json"])
                       for kind in ("source", "image")}
        refdir = REFERENCES / old["id"]
        refprov = read(refdir / "provenance.json")
        reference = read(refdir / "sbom.json", refprov["reference"]["sha256"])
        if not (refprov["commit"] == provenance["git"]["commit"] == manifest[old["id"]]["commit"]):
            raise ValueError("Commit mismatch")
        pools = {kind: [(a.get("purl"), coordinate(a.get("purl"))) for a in doc["artifacts"]]
                 for kind, doc in inventories.items()}
        pools["final"] = [(c.get("purl"), coordinate(c.get("purl"))) for c in components(final)]
        edges = []
        for ref, purl in direct_edges(refprov, reference, refdir):
            key = coordinate(purl)
            observations = {kind: observation(key, pool) for kind, pool in pools.items()}
            evidence = declaration_evidence(manifest[old["id"]], key) if observations["image"]["state"] == "not_observed" else None
            edges.append({"reference_ref": ref, "reference_purl": purl,
                          "declaration_evidence": evidence, **observations})
            totals.update({f"{kind}:{value['state']}": 1 for kind, value in observations.items()})
        if len(edges) != refprov["direct_edges"]:
            raise ValueError("Reference edge receipt mismatch")
        blockers = ["Build/image linkage unverified", "Build profile and per-edge scopes not fully reconciled",
                    "B0 does not predict direct dependency ownership; its inventory is not a direct prediction set"]
        if not edges:
            blockers.append("Empty root graph gives no positive version-pairing evidence")
        if refprov.get("benchmark_packaging_overlay"):
            blockers.append("Reference adds packaging absent from original image recipe")
        rows.append({"id": old["id"], "language": old["language"], "commit": refprov["commit"],
                     "image_config_digest": provenance["image"]["image_config_digest"],
                     "reference_sha256": refprov["reference"]["sha256"], "final_sha256": old["final_sha256"],
                     "input_hashes": provenance["input_hashes"], "direct_edge_count": len(edges),
                     "image_coordinate_counts": dict(Counter(e["image"]["state"] for e in edges)),
                     "pair_verified": False, "blockers": blockers, "edges": edges})
    return {"schema_version": 1, "reference_commit": "1b41c109c4c0d64335578737b6fea569fe23bd7f",
            "baseline_implementation": "20f287b60d358692c843526704cd44e71ed4012f",
            "comparison": "PURL ecosystem/namespace/name/version only; qualifiers/subpath retained in evidence, ignored for diagnostic matching",
            "accuracy": {"precision": None, "recall": None, "f1": None, "reason": "unverified pairs and no direct predictions"},
            "counts": dict(sorted(totals.items())), "rows": rows}


def main():
    result = audit()
    output = ROOT / "docs/reference-pairing-audit-v1.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    lines = ["# R2: сопоставимость эталонов R1 и образов B0", "",
             "Это диагностика координат пакетов, не оценка precision/recall и не доказательство парности сборки и образа.",
             "Проверены commit и сохранённые SHA-256 source/image Syft, final CycloneDX и сборочных эталонов.",
             "Сравниваются ecosystem/namespace/name/version; qualifiers и subpath не используются как доказательство идентичности.", "",
             "| Язык | Прямых рёбер R1 | Та же координата в образе | Только другая версия | Не обнаружено | Нет координаты |",
             "|---|---:|---:|---:|---:|---:|"]
    for language in ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby"):
        subset = [r for r in result["rows"] if r["language"] == language]
        counts = Counter()
        for row in subset:
            counts.update(row["image_coordinate_counts"])
        values = [counts[x] for x in ("same_coordinate", "other_version_only", "not_observed", "reference_coordinate_unresolved")]
        lines.append(f"| {language} | {sum(r['direct_edge_count'] for r in subset)} | " + " | ".join(map(str, values)) + " |")
    lines += ["", "Отсутствующее ребро не называется FN: provided/build-only зависимости, target/features и локальные workspace-модули могут отличаться от содержимого образа.",
              "Совпадение координат не называется TP: это не доказывает прямую связь, происхождение сборки или полную идентичность артефакта.",
              "У 30 проектов нет положительных прямых рёбер: пустота не подтверждает парность и не даёт 100% точности.",
              "", "Проверка точных Git blob деклараций: все 15 отсутствующих Rust-компонентов объявлены в build-dependencies; три Java-компонента — provided, два — optional. Optional сам по себе не объясняет отсутствие: эти два случая остаются неразобранными.",
              "Другие версии: MarkupSafe 3.0.4 в эталонах jinja/werkzeug против 3.0.3 в старых образах; psych: date 3.6.0 против 3.3.4 и stringio 3.2.0 против 3.1.1. Эти пары не допускаются к оценке точных версий.",
              "", "Следующий этап: выбрать непустой проект, экспортировать его runtime-образ и CycloneDX из одной сборки с закреплённым профилем. Согласовать direct-рёбра с декларациями; эталон не передавать сервису.",
              "", "[Полный отчёт с рёбрами и версиями](reference-pairing-audit-v1.json). Повтор: `python benchmarks/audit_reference_pairing.py`."]
    (ROOT / "docs/reference-pairing-audit-v1.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result["counts"], ensure_ascii=False))


if __name__ == "__main__":
    main()

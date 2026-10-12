"""External, resumable build-time CycloneDX reference collection (never service code)."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime

from jsonschema import Draft7Validator, ValidationError
from referencing import Registry, Resource
from run import ROOT, atomic_json, recipe, run_command

from sbom_creator.validation import schema

WORK = ROOT / "benchmarks/.work/build-references-v1"
OUT = ROOT / "benchmarks/results/build-references-v1"
VERSIONS = {"Java": "2.9.3", "JavaScript": "6.0.1", "Python": "7.5.0",
            "Rust": "0.5.9", "Go": "1.12.0", "Ruby": "git:7efedd6422cc32d9bdefbb6eddb7b4eaa3857309"}


def dockerfile(row):
    language = row["language"]
    prefix = ""
    if language == "Java":
        # Invoke a pinned Maven plugin in the same reactor/lifecycle as package.
        build = recipe(row).split("FROM eclipse-temurin:")[0]
        build = build.replace("package dependency:copy-dependencies", "package org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom -DoutputFormat=json -DoutputName=sbom -DincludeTestScope=false dependency:copy-dependencies")
        module = {"java-gson": "gson", "java-slf4j": "slf4j-api"}.get(row["id"])
        if module:
            build += f"RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -pl {module} org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DoutputName=sbom -DincludeTestScope=false\n"
        build += "RUN mkdir /reference && find . -name '*bom*.json' -path '*/target/*' -exec cp --parents {} /reference/ \\;\n"
    elif language == "JavaScript":
        build = """FROM node:22-bookworm-slim AS build
RUN npm install --global @cyclonedx/cyclonedx-npm@6.0.1
WORKDIR /src
COPY src/ /src/
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund && mkdir /reference && npm pack --ignore-scripts --pack-destination /reference && cyclonedx-npm --omit dev --spec-version 1.6 --output-file /reference/sbom.json && npm ls --all --omit=dev --json > /reference/resolved.json
"""
        if row["id"] in {"javascript-axios", "javascript-lodash"}:
            build = build.replace("npm install --omit=dev --ignore-scripts", "npm install --ignore-scripts")
            build = build.replace("mkdir /reference && npm pack --ignore-scripts --pack-destination /reference", "mkdir /reference && npm run build && npm prune --omit=dev --ignore-scripts")
    elif language == "Python":
        plain = row.get("build_system") == "plain"
        install = "/project/bin/pip install /src && /project/bin/pip inspect > /reference/resolved.json"
        root = "--pyproject /src/pyproject.toml" if (WORK / row["id"] / "src/pyproject.toml").exists() else ""
        if row["id"] == "python-python-certifi":
            # This commit uses setup.py. Give the official generator its root via
            # PEP 621 metadata derived from the package that was actually built.
            install += " && /project/bin/python -c 'import importlib.metadata as m,json; d=m.distribution(\"certifi\"); open(\"/reference/root.pyproject.toml\",\"w\").write(\"[project]\\nname = \"+json.dumps(d.metadata[\"Name\"])+\"\\nversion = \"+json.dumps(d.version)+\"\\ndependencies = \"+json.dumps(d.requires or [])+\"\\n\")'"
            root = "--pyproject /reference/root.pyproject.toml"
        build = f"""FROM python:3.12-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* && python -m venv /generator && /generator/bin/pip install cyclonedx-bom==7.5.0
WORKDIR /src
COPY src/ /src/
RUN mkdir /reference && python -m venv /project && {install} && /generator/bin/cyclonedx-py environment /project/bin/python {root} --spec-version 1.6 --output-file /reference/sbom.json
"""
        if plain:
            build = build.replace("RUN mkdir /reference", "COPY plain_python_reference.toml /src/pyproject.toml\nRUN mkdir /reference")
            build = build.replace("/project/bin/python  --spec-version", "/project/bin/python --pyproject /src/pyproject.toml --spec-version")
            build += "RUN cp /src/pyproject.toml /reference/root.pyproject.toml\n"
    elif language == "Rust":
        build = recipe(row).split("FROM debian:")[0]
        build = build.replace("WORKDIR /src", "RUN cargo install cargo-cyclonedx --version 0.5.9 --locked\nWORKDIR /src")
        build += "RUN --mount=type=cache,target=/usr/local/cargo/registry cargo cyclonedx --format json --spec-version 1.5 --override-filename sbom && mkdir /reference && find . -name sbom.json -not -path './target/*' -exec cp --parents {} /reference/ \\; && cargo metadata --locked --format-version 1 > /reference/resolved.json\n"
    elif language == "Go":
        prefix = """FROM golang:1.26-bookworm AS generator
RUN GOBIN=/tools go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
"""
        build = recipe(row).split("FROM debian:")[0]
        build = build.replace("WORKDIR /src", "COPY --from=generator /tools/cyclonedx-gomod /usr/local/bin/\nWORKDIR /src")
        main = "cmd/upterm" if row["id"] == "go-upterm" else "."
        # A module-less project needs an explicit, recorded benchmark-only overlay.
        init = "go mod init github.com/tomnomnom/assetfinder && " if row["id"] == "go-assetfinder" else ""
        build += f"RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod mkdir /reference && {init}cyclonedx-gomod app -json -output /reference/sbom.json -main {main} . && cp /out/go-build-info.txt /reference/ && go list -deps -json {main} > /reference/resolved.json\n"
    elif language == "Ruby":
        build = """FROM ruby:3.3-bookworm AS build
RUN git clone https://github.com/CycloneDX/cyclonedx-ruby-gem.git /generator && cd /generator && git checkout 7efedd6422cc32d9bdefbb6eddb7b4eaa3857309 && gem build cyclonedx-ruby.gemspec && gem install --no-document *.gem
WORKDIR /src
COPY src/ /src/
RUN gem build *.gemspec && mkdir /reference && cp *.gem /reference/ && gem install --no-document /reference/*.gem
RUN mkdir /resolution && printf 'source "https://rubygems.org"\\n' > /resolution/Gemfile && ruby -e 's=Gem::Package.new(Dir["/reference/*.gem"].first).spec; File.open("/resolution/Gemfile", "a") { |f| f.puts "gem #{s.name.inspect}, path: \\\"/src\\\"" }' -rrubygems/package
RUN cd /resolution && bundle lock && bundle install && cyclonedx-ruby -p /resolution -f json -s 1.6 -o /reference/sbom.json && cp Gemfile Gemfile.lock /reference/
COPY ruby_reference_graph.rb /native-graph.rb
RUN cd /resolution && ruby /native-graph.rb
"""
    else:
        raise ValueError(language)
    return prefix + build + "FROM scratch AS export\nCOPY --from=build /reference/ /\n"


def inspect_bom(path):
    data = json.loads(path.read_text("utf-8"))
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("not CycloneDX")
    version = data.get("specVersion")
    if version not in {"1.5", "1.6"}:
        raise ValueError(f"unsupported reference schema: {version}")
    name = f"bom-{version}.schema.json"
    document_schema = (json.loads((ROOT / "benchmarks/schemas" / name).read_text("utf-8"))
                       if version == "1.5" else schema(name))
    registry = Registry()
    for filename, content in [(name, document_schema), ("spdx.schema.json", schema("spdx.schema.json")),
                              ("jsf-0.82.schema.json", schema("jsf-0.82.schema.json"))]:
        for address in (filename, f"http://cyclonedx.org/schema/{filename}", f"https://cyclonedx.org/schema/{filename}"):
            registry = registry.with_resource(address, Resource.from_contents(content))
    Draft7Validator(document_schema, registry=registry).validate(data)
    components = []
    def collect(items):
        for item in items:
            components.append(item)
            collect(item.get("components", []))
    collect(data.get("components", []))
    root = data.get("metadata", {}).get("component", {})
    collect([root] if root else [])
    refs = {c["bom-ref"] for c in components if "bom-ref" in c}
    if len(refs) != sum("bom-ref" in c for c in components):
        raise ValueError("duplicate component reference")
    graph = data.get("dependencies", [])
    for edge in graph:
        if edge["ref"] not in refs or not set(edge.get("dependsOn", [])) <= refs:
            raise ValueError("dangling dependency graph reference")
    root_edges = [e for e in graph if e["ref"] == root.get("bom-ref")]
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "spec_version": data["specVersion"], "schema_valid": True, "components": len(components),
            "dependency_entries": len(graph), "root": root.get("bom-ref"),
            "root_graph_present": bool(root_edges),
            "direct_edges": len(root_edges[0].get("dependsOn", [])) if root_edges else None}


def run(row):
    case = WORK / row["id"]
    target = OUT / row["id"]
    case.mkdir(parents=True, exist_ok=True)
    if (target / "result.json").exists():
        previous = json.loads((target / "result.json").read_text("utf-8"))
        atomic_json(case / "history" / (datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + ".json"), previous)
    result = {"id": row["id"], "language": row["language"], "commit": row["commit"],
              "generator_version": VERSIONS[row["language"]], "status": "running",
              "started_at": datetime.now(UTC).isoformat(), "old_image_pair_verified": False}
    atomic_json(target / "result.json", result)
    try:
        src = case / "src"
        if not src.exists():
            run_command(["git", "clone", "--no-hardlinks", "--no-checkout", str(ROOT / "benchmarks/.work" / row["id"] / "src"), str(src)], case / "clone.log")
        run_command(["git", "-c", "core.autocrlf=false", "-c", "core.longpaths=true", "checkout", "--force", "--detach", row["commit"]], case / "checkout.log", cwd=src)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src, text=True).strip()
        if head != row["commit"]:
            raise ValueError("checkout commit mismatch")
        text = dockerfile(row)
        if row["language"] == "Ruby":
            shutil.copyfile(ROOT / "benchmarks/ruby_reference_graph.rb", case / "ruby_reference_graph.rb")
        if row.get("build_system") == "plain":
            shutil.copyfile(ROOT / "benchmarks/plain_python_reference.toml", case / "plain_python_reference.toml")
        (case / "Dockerfile").write_text(text, encoding="utf-8", newline="\n")
        (target / "Dockerfile").write_text(text, encoding="utf-8", newline="\n")
        result["recipe_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        result["recipe_inputs"] = {name: hashlib.sha256((case / name).read_bytes()).hexdigest()
                                   for name in ("ruby_reference_graph.rb", "plain_python_reference.toml")
                                   if (case / name).exists()}
        artifacts = target / ("artifacts-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f"))
        run_command(["docker", "build", "--progress=plain", "--output", f"type=local,dest={artifacts}", str(case)], case / "build.log", timeout=5400)
        boms = [p for p in sorted(artifacts.rglob("*.json"))
                if p.name != "resolved.json" and json.loads(p.read_text("utf-8")).get("bomFormat") == "CycloneDX"]
        if not boms:
            raise ValueError("build completed without reference SBOM")
        result["boms"] = [inspect_bom(p) for p in boms]
        result["status"] = "generated"
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, ValidationError) as exc:
        result.update(status="failed", error=str(exc))
    result["finished_at"] = datetime.now(UTC).isoformat()
    if (case / "build.log").exists():
        result["build_log_sha256"] = hashlib.sha256((case / "build.log").read_bytes()).hexdigest()
    atomic_json(target / "result.json", result)
    print(row["id"], result["status"], result.get("error", ""), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--language")
    parser.add_argument("--id")
    parser.add_argument("--retry", action="store_true")
    args = parser.parse_args()
    rows = json.loads((ROOT / "benchmarks/manifest.json").read_text("utf-8"))["repositories"]
    statuses = []
    for row in rows:
        if args.language and row["language"] != args.language or args.id and row["id"] != args.id:
            continue
        previous = OUT / row["id"] / "result.json"
        if previous.exists() and not args.retry:
            statuses.append(json.loads(previous.read_text("utf-8"))["status"])
            continue
        statuses.append(run(row)["status"])
    return 0 if statuses and all(status == "generated" for status in statuses) else 1


if __name__ == "__main__":
    raise SystemExit(main())

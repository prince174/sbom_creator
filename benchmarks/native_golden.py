"""Six controlled native builds with labels fixed before scanning; no model.

Generated applications and metadata-only/removed controls are not production
ground truth. Only explicitly labelled identities participate in FP/FN metrics.
The final image retains a language runtime for a constrained positive smoke test.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbom_creator.acquire import Settings, clean_environment, run_command
from sbom_creator.core import rules_assessor
from sbom_creator.pipeline import analyze_local, publish_catalogs, sha256, write_json

LANGUAGES = ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby")


def put(root, name, value):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value, encoding="utf-8", newline="\n")


def wheel(root, name, version):
    normalized = name.replace("-", "_")
    info = f"{normalized}-{version}.dist-info"
    files = {f"{normalized}/__init__.py": f"print('golden-{version}')\n",
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        f"{info}/WHEEL": "Wheel-Version: 1.0\nGenerator: controlled-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    files[f"{info}/RECORD"] = "".join(f"{n},,\n" for n in files) + f"{info}/RECORD,,\n"
    with zipfile.ZipFile(root / f"{normalized}-{version}-py3-none-any.whl", "x") as archive:
        for entry_name, content in files.items():
            archive.writestr(entry_name, content)


def create(case: Path, language: str):
    source = case / "src"
    source.mkdir(parents=True)
    # Go major v2 requires a /v2 module path. Use two valid v1 releases so the
    # multi-version control has the same module identity, not an invalid tag.
    second = "1.1.0" if language == "Go" else "2.0.0"
    names = [("kept", "1.0.0"), ("kept", second), ("orphan", "1.0.0"), ("removed", "1.0.0")]
    prefix = "golden-" + language.lower()
    ecosystem = {"Java": "maven/org.example", "JavaScript": "npm", "Python": "pypi",
                 "Ruby": "gem", "Rust": "cargo", "Go": "golang/example.test"}[language]
    version_prefix = "v" if language == "Go" else ""
    purl = lambda name, version: f"pkg:{ecosystem}/{prefix}-{name}@{version_prefix}{version}"
    labels = {"language": language, "positive": [purl("kept", "1.0.0"), purl("kept", second)],
        "negative": [purl("orphan", "1.0.0"), purl("removed", "1.0.0"), purl("dev", "1.0.0")],
        "scope": "Controlled labelled identities only; other runtime/base packages are not ground-truth labelled."}
    commands, removed = [], []
    if language == "Python":
        base = runtime = "python:3.12-slim-bookworm"
        for name, version in names:
            full = prefix + "-" + name
            wheel(source, full, version)
            dest = f"/out/opt/{name}-{version}/lib/python3.12/site-packages"
            commands.append(f"python -m pip install --no-deps --no-index --target {dest} /src/{full.replace('-', '_')}-{version}-py3-none-any.whl")
            if name == "orphan":
                commands.append(f"rm -r {dest}/{full.replace('-', '_')}")
            if name == "removed":
                removed.append(f"/opt/{name}-{version}")
        put(source, "requirements.txt", "\n".join(f"{prefix}-{n}=={v}" for n, v in names) + f"\n{prefix}-dev==1.0.0\n")
        commands.append("mkdir -p /out/app && cp requirements.txt /out/app/requirements.txt")
        smoke = ["python", "-c", f"import sys; sys.path.insert(0,'/opt/kept-1.0.0/lib/python3.12/site-packages'); import {prefix.replace('-', '_')}_kept"]
    elif language == "JavaScript":
        base = runtime = "node:22-bookworm-slim"
        for name, version in names:
            folder, full = f"{name}-{version}", prefix + "-" + name
            put(source, folder + "/package.json", json.dumps({"name": full, "version": version, "main": "index.js"}))
            put(source, folder + "/index.js", f"console.log('golden-{version}');\n")
            commands.append(f"cd /src/{folder} && npm pack --ignore-scripts --pack-destination /src && cd /src")
            commands.append(f"npm install --prefix /out/opt/{folder} --offline --ignore-scripts --no-audit --no-fund /src/{full}-{version}.tgz")
            if name == "orphan":
                commands.append(f"rm /out/opt/{folder}/node_modules/{full}/index.js")
            if name == "removed":
                removed.append(f"/opt/{folder}")
        put(source, "package-lock.json", json.dumps({"name": "source", "lockfileVersion": 3,
            "packages": {f"node_modules/{prefix}-dev": {"version": "1.0.0", "dev": True}}}))
        smoke = ["node", f"/opt/kept-1.0.0/node_modules/{prefix}-kept/index.js"]
    elif language == "Ruby":
        base = runtime = "ruby:3.3-slim-bookworm"
        for name, version in names:
            folder, full = f"{name}-{version}", prefix + "-" + name
            put(source, folder + "/lib/golden.rb", f"puts 'golden-{version}'\n")
            put(source, folder + "/fixture.gemspec", f"Gem::Specification.new do |s|\ns.name='{full}'\ns.version='{version}'\ns.summary='controlled fixture'\ns.authors=['fixture']\ns.files=['lib/golden.rb']\nend\n")
            commands.append(f"cd /src/{folder} && gem build fixture.gemspec && gem install --local --no-document --install-dir /out/opt/gems {full}-{version}.gem && cd /src")
            if name == "orphan":
                commands.append(f"rm /out/opt/gems/gems/{full}-{version}/lib/golden.rb")
            if name == "removed":
                removed += [f"/opt/gems/gems/{full}-{version}", f"/opt/gems/specifications/{full}-{version}.gemspec", f"/opt/gems/cache/{full}-{version}.gem"]
        put(source, "Gemfile.lock", f"GEM\n  specs:\n    {prefix}-dev (1.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  {prefix}-dev\n")
        # Installed gem caches are archives, not the delivered library payload.
        commands.append("rm -rf /out/opt/gems/cache /out/opt/gems/build_info")
        smoke = ["ruby", f"/opt/gems/gems/{prefix}-kept-1.0.0/lib/golden.rb"]
    elif language == "Java":
        base, runtime = "maven:3.9.11-eclipse-temurin-21", "eclipse-temurin:17-jre-jammy"
        for name, version in names:
            folder, full = f"{name}-{version}", prefix + "-" + name
            put(source, folder + "/Golden.java", f'public class Golden {{ public static void main(String[] args) {{ System.out.println("golden-{version}"); }} }}\n')
            put(source, folder + f"/META-INF/maven/org.example/{full}/pom.properties", f"groupId=org.example\nartifactId={full}\nversion={version}\n")
            commands.append(f"cd /src/{folder} && javac --release 17 Golden.java && mkdir -p /out/app && jar --create --file /out/app/{full}-{version}.jar --main-class Golden Golden.class META-INF && cd /src")
            if name == "orphan":
                commands.append(f"cd /src/{folder} && jar --create --file /out/app/{full}-{version}.jar META-INF && cd /src")
            if name == "removed":
                removed.append(f"/app/{full}-{version}.jar")
        put(source, "pom.xml", f'<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>source</artifactId><version>1.0.0</version><dependencies><dependency><groupId>org.example</groupId><artifactId>{prefix}-dev</artifactId><version>1.0.0</version><scope>test</scope></dependency></dependencies></project>')
        smoke = ["java", "-jar", f"/app/{prefix}-kept-1.0.0.jar"]
    elif language == "Go":
        base, runtime = "golang:1.24-bookworm", "debian:bookworm-slim"
        for name, version in [x for x in names if x[0] != "orphan"]:
            folder, full = f"{name}-{version}", prefix + "-" + name
            put(source, folder + "/go.mod", f"module example.test/{full}\n\ngo 1.24.0\n")
            put(source, folder + "/main.go", f'package main\nimport "fmt"\nfunc main() {{ fmt.Println("golden-{version}") }}\n')
            commands.append(f"cd /src/{folder} && git init -q && git config user.name fixture && git config user.email fixture@example.test && git add . && git commit -qm fixture && git tag v{version} && CGO_ENABLED=0 GOMAXPROCS=2 GOPROXY=off go build -buildvcs=true -o /out/app/{full}-{version} . && cd /src")
            if name == "removed":
                removed.append(f"/app/{full}-{version}")
        put(source, "declarations/go.mod", f"module example.test/declarations\ngo 1.24.0\nrequire (\n example.test/{prefix}-dev v1.0.0\n example.test/{prefix}-orphan v1.0.0\n)\n")
        commands.append("mkdir -p /out/app/declarations && cp declarations/go.mod /out/app/declarations/")
        labels["positive"].append("pkg:golang/stdlib@1.24.13")
        smoke = [f"/app/{prefix}-kept-1.0.0"]
    else:
        base, runtime = "rust:1.85.1-bookworm", "debian:bookworm-slim"
        for name, version in [x for x in names if x[0] != "orphan"]:
            folder, full = f"{name}-{version}", prefix + "-" + name
            put(source, folder + "/Cargo.toml", f'[package]\nname="{full}"\nversion="{version}"\nedition="2021"\n')
            put(source, folder + "/src/main.rs", f'fn main() {{ println!("golden-{version}"); }}\n')
            commands.append(f"cd /src/{folder} && cargo auditable build --offline && mkdir -p /out/app && cp target/debug/{full} /out/app/{full}-{version} && cd /src")
            if name == "removed":
                removed.append(f"/app/{full}-{version}")
        put(source, "Cargo.lock", 'version = 3\n' + ''.join(f'\n[[package]]\nname = "{prefix}-{n}"\nversion = "1.0.0"\n' for n in ['orphan', 'dev']))
        commands.append("mkdir -p /out/app && cp Cargo.lock /out/app/")
        smoke = [f"/app/{prefix}-kept-1.0.0"]
    header = f"FROM {base} AS build\n"
    if language == "Rust":
        header += "ENV RUSTUP_TOOLCHAIN=1.85.1 CARGO_BUILD_JOBS=2\nRUN cargo install cargo-auditable --version 0.6.6 --locked\n"
    header += "WORKDIR /src\nCOPY src/ /src/\n"
    recipe = header + "RUN " + " && ".join(commands) + f"\nFROM {runtime}\nCOPY --from=build /out/ /\n"
    recipe += "RUN rm -rf " + " ".join(removed) + "\n"
    recipe += 'CMD ["/bin/true"]\n'
    put(case, "Dockerfile", recipe)
    put(case, ".dockerignore", "*\n!src/\n!src/**\n!Dockerfile\n")
    write_json(case / "ground-truth.json", labels)
    return labels, smoke


def assess(case, labels, output):
    cdx = json.loads((output / "final.cdx.json").read_bytes())
    observed = {a.get("purl") for a in cdx.get("components", [])}
    positive, negative = set(labels["positive"]), set(labels["negative"])
    return {"language": labels["language"], "positive": sorted(positive), "negative": sorted(negative),
        "tp": len(positive & observed), "fp": sorted(negative & observed), "fn": sorted(positive - observed),
        "unlabelled_final_identities": len(observed - positive - negative),
        "ground_truth_sha256": sha256(case / "ground-truth.json"), "analysis_directory": str(output),
        "final_sha256": sha256(output / "final.cdx.json"), "scope": labels["scope"]}


def run(work, report, syft, replay=False):
    if report.exists():
        raise FileExistsError("Keep old reports; choose a new report path")
    rows = []
    settings = Settings(syft_binary=syft, pull_image=False, registry_hosts=("docker.io",))
    for language in LANGUAGES:
        case = work / language.lower()
        start = time.monotonic()
        if replay:
            labels = json.loads((case / "ground-truth.json").read_bytes())
            old = case / "baseline"
            output = case / ("replay-" + str(time.time_ns()))
            provenance = json.loads((old / "provenance.json").read_bytes())
            provenance["replay_of"] = str(old)
            publish_catalogs(json.loads((old / "source.syft.json").read_bytes()),
                             json.loads((old / "image.syft.json").read_bytes()),
                             output, settings, rules_assessor, provenance)
            smoke = json.loads((case / "smoke.json").read_bytes())
        else:
            if case.exists():
                raise FileExistsError("Use a fresh work directory; native fixtures are immutable")
            labels, command = create(case, language)
            label_hash = sha256(case / "ground-truth.json")
            reference = "docker.io/sbom-native-golden/" + language.lower() + ":" + label_hash[:12]
            result = subprocess.run(["docker", "build", "--progress=plain", "-t", reference, str(case)],
                                    capture_output=True, timeout=900, check=False)
            (case / "build.log").write_bytes(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f"{language} build failed; see its local build.log")
            output = case / "baseline"
            analyze_local(case / "src", reference, output, settings)
            image_id = json.loads((output / "provenance.json").read_bytes())["image"]["image_id"]
            text = run_command(["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--memory=256m", "--cpus=1", "--pids-limit=64",
                image_id, *command], cwd=case, env=clean_environment(), timeout=30,
                max_output_bytes=8192, label="Controlled positive smoke")
            if "golden-1.0.0" not in text:
                raise AssertionError("Controlled payload smoke returned unexpected output")
            smoke = {"passed": True, "image_id": image_id, "command": command, "output": text.strip()}
            write_json(case / "smoke.json", smoke)
            assert sha256(case / "ground-truth.json") == label_hash
        row = assess(case, labels, output)
        row.update(smoke=smoke, seconds=round(time.monotonic() - start, 3))
        rows.append(row)
        report.parent.mkdir(parents=True, exist_ok=True)
        write_json(report, {"complete": len(rows) == 6, "rows": rows,
            "passed": len(rows) == 6 and all(not r["fp"] and not r["fn"] for r in rows)})
        print(language, "TP", row["tp"], "FP", row["fp"], "FN", row["fn"], flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--syft", required=True)
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    run(args.work.resolve(), args.report.resolve(), args.syft, args.replay)

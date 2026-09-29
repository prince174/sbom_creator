"""Resolve public release tags to immutable commits for the 60 repository matrix.

This is a source list, not a declaration that a build or benchmark passed.
"""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
from pathlib import Path

REPOSITORIES = {
    "Java": [
        ("apache/commons-lang", "rel/commons-lang-3.17.0", "org.apache.commons:commons-lang3", "3.17.0"),
        ("apache/commons-io", "rel/commons-io-2.18.0", "commons-io:commons-io", "2.18.0"),
        ("apache/commons-codec", "rel/commons-codec-1.17.1", "commons-codec:commons-codec", "1.17.1"),
        ("apache/commons-text", "rel/commons-text-1.13.0", "org.apache.commons:commons-text", "1.13.0"),
        ("apache/commons-csv", "rel/commons-csv-1.13.0", "org.apache.commons:commons-csv", "1.13.0"),
        ("apache/commons-compress", "rel/commons-compress-1.27.1", "org.apache.commons:commons-compress", "1.27.1"),
        ("google/gson", "gson-parent-2.11.0", "com.google.code.gson:gson", "2.11.0"),
        ("jhy/jsoup", "jsoup-1.18.3", "org.jsoup:jsoup", "1.18.3"),
        ("qos-ch/slf4j", "v_2.0.16", "org.slf4j:slf4j-api", "2.0.16"),
        ("apache/commons-cli", "rel/commons-cli-1.9.0", "commons-cli:commons-cli", "1.9.0"),
    ],
    "JavaScript": [
        ("lodash/lodash", "4.17.21", "lodash", "4.17.21"),
        ("expressjs/express", "4.21.2", "express", "4.21.2"),
        ("axios/axios", "v1.7.9", "axios", "1.7.9"),
        ("debug-js/debug", "4.4.0", "debug", "4.4.0"),
        ("vercel/ms", "2.1.3", "ms", "2.1.3"),
        ("chalk/chalk", "v5.4.1", "chalk", "5.4.1"),
        ("tj/commander.js", "v13.1.0", "commander", "13.1.0"),
        ("minimistjs/minimist", "v1.2.8", "minimist", "1.2.8"),
        ("jonschlinkert/is-number", "7.0.0", "is-number", "7.0.0"),
        ("juliangruber/isarray", "v2.0.5", "isarray", "2.0.5"),
    ],
    "Python": [
        ("psf/requests", "v2.32.3", "requests", "2.32.3"),
        ("encode/httpx", "0.28.1", "httpx", "0.28.1"),
        ("pallets/click", "8.1.8", "click", "8.1.8"),
        ("pallets/flask", "3.1.0", "flask", "3.1.0"),
        ("pallets/jinja", "3.1.5", "jinja2", "3.1.5"),
        ("pallets/werkzeug", "3.1.3", "werkzeug", "3.1.3"),
        ("pallets/itsdangerous", "2.2.0", "itsdangerous", "2.2.0"),
        ("python-attrs/attrs", "24.3.0", "attrs", "24.3.0"),
        ("pypa/packaging", "24.2", "packaging", "24.2"),
        ("certifi/python-certifi", "2024.12.14", "certifi", "2024.12.14"),
    ],
    "Rust": [
        ("BurntSushi/ripgrep", "14.1.1", "ripgrep", "14.1.1"),
        ("sharkdp/fd", "v10.2.0", "fd-find", "10.2.0"),
        ("sharkdp/bat", "v0.25.0", "bat", "0.25.0"),
        ("bootandy/dust", "v1.1.1", "du-dust", "1.1.1"),
        ("ClementTsang/bottom", "0.10.2", "bottom", "0.10.2"),
        ("XAMPPRocky/tokei", "v12.1.2", "tokei", "12.1.2"),
        ("sharkdp/hyperfine", "v1.19.0", "hyperfine", "1.19.0"),
        ("eza-community/eza", "v0.20.15", "eza", "0.20.15"),
        ("ajeetdsouza/zoxide", "v0.9.6", "zoxide", "0.9.6"),
        ("dandavison/delta", "0.18.2", "git-delta", "0.18.2"),
    ],
    "Go": [
        ("rakyll/hey", "v0.1.4", "github.com/rakyll/hey", "v0.1.4"),
        ("tomnomnom/assetfinder", "v0.1.1", "github.com/tomnomnom/assetfinder", "v0.1.1"),
        ("tomnomnom/httprobe", "v0.2", "github.com/tomnomnom/httprobe", "v0.2.0"),
        ("tomnomnom/waybackurls", "v0.1.0", "github.com/tomnomnom/waybackurls", "v0.1.0"),
        ("tomnomnom/unfurl", "v0.4.3", "github.com/tomnomnom/unfurl", "v0.4.3"),
        ("mikefarah/yq", "v4.44.6", "github.com/mikefarah/yq/v4", "v4.44.6"),
        ("jesseduffield/lazygit", "v0.44.1", "github.com/jesseduffield/lazygit", "v0.44.1"),
        ("charmbracelet/glow", "v2.0.0", "github.com/charmbracelet/glow/v2", "v2.0.0"),
        ("boyter/scc", "v3.5.0", "github.com/boyter/scc/v3", "v3.5.0"),
        ("owenthereal/upterm", "v0.14.3", "github.com/owenthereal/upterm", "v0.14.3"),
    ],
    "Ruby": [
        ("ruby/rake", "v13.2.1", "rake", "13.2.1"),
        ("rack/rack", "v3.1.8", "rack", "3.1.8"),
        ("ruby/psych", "v5.2.2", "psych", "5.2.2"),
        ("ruby/json", "v2.9.1", "json", "2.9.1"),
        ("ruby/rexml", "v3.3.9", "rexml", "3.3.9"),
        ("ruby/csv", "v3.3.2", "csv", "3.3.2"),
        ("ruby/bigdecimal", "v3.1.8", "bigdecimal", "3.1.8"),
        ("ruby/logger", "v1.6.4", "logger", "1.6.4"),
        ("ruby/uri", "v1.0.2", "uri", "1.0.2"),
        ("ruby/stringio", "v3.1.2", "stringio", "3.1.2"),
    ],
}


def resolve(entry: tuple[str, tuple[str, str, str, str]]) -> dict:
    language, (repository, ref, package, version) = entry
    url = f"https://github.com/{repository}.git"
    result = subprocess.run(
        ["git", "ls-remote", url, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=90, check=True,
    )
    refs = dict(line.split()[::-1] for line in result.stdout.splitlines() if line.strip())
    commit = refs.get(f"refs/tags/{ref}^{{}}", refs.get(f"refs/tags/{ref}"))
    return {
        "id": language.lower() + "-" + repository.split("/")[-1].lower().replace(".", "-"),
        "language": language, "repository_url": url, "release_ref": ref,
        "commit": commit, "expected_package": package, "expected_version": version,
        "source_host": "github.com", "image_kind": "controlled-source-build",
        "build_link": "benchmark-recipe; not upstream attestation",
        "resolution_status": "resolved" if commit else "tag_not_found",
    }


def main() -> None:
    rows = [(language, row) for language, entries in REPOSITORIES.items() for row in entries]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        resolved = list(executor.map(resolve, rows))
    data = {"schema_version": 1, "description": "60 distinct public release repositories; 10 per language. A manifest row is not a successful test.", "repositories": resolved}
    target = Path(__file__).with_name("manifest.json")
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for row in resolved:
        print(row["language"], row["id"], row["resolution_status"], row["commit"] or row["release_ref"])


if __name__ == "__main__":
    main()

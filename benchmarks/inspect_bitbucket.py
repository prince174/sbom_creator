"""Read-only Bitbucket inventory, using only existing runtime reader credentials."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def credentials(path: Path) -> dict[str, str]:
    allowed = {"BITBUCKET_WORKSPACE", "BITBUCKET_EMAIL", "BITBUCKET_TOKEN"}
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        key, separator, value = line.strip().partition("=")
        if separator and key in allowed:
            result[key] = value.strip().strip('"').strip("'")
    if not allowed <= result.keys():
        raise ValueError("Runtime Bitbucket reader settings are incomplete")
    return result


def read_json(url: str, secret: dict[str, str]) -> dict:
    # Follow only API pagination URLs. Neither credentials nor headers are logged.
    if not url.startswith("https://api.bitbucket.org/2.0/"):
        raise ValueError("Unexpected API pagination origin")
    auth = base64.b64encode((secret["BITBUCKET_EMAIL"] + ":" + secret["BITBUCKET_TOKEN"]).encode()).decode()
    request = Request(url, headers={"Authorization": "Basic " + auth, "Accept": "application/json"}, method="GET")
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path(r"G:\code\artifact_graph\.env"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("bitbucket-inventory.json"))
    args = parser.parse_args()
    secret = credentials(args.env_file)
    url = "https://api.bitbucket.org/2.0/repositories/" + secret["BITBUCKET_WORKSPACE"] + "?pagelen=100"
    rows = []
    while url:
        data = read_json(url, secret)
        for repo in data["values"]:
            slug = repo["slug"]
            commits = read_json("https://api.bitbucket.org/2.0/repositories/" + secret["BITBUCKET_WORKSPACE"] + "/" + slug + "/commits?pagelen=1", secret)
            commit = commits.get("values", [{}])[0].get("hash")
            rows.append({"slug": slug, "language": repo.get("language"), "mainbranch": repo.get("mainbranch", {}).get("name"),
                         "commit": commit, "repository_url": "https://bitbucket.org/" + secret["BITBUCKET_WORKSPACE"] + "/" + slug + ".git",
                         "private": repo.get("is_private"), "description": repo.get("description")})
            print(slug, repo.get("language") or "unspecified", commit, flush=True)
        url = data.get("next")
    args.output.write_text(json.dumps({"workspace": secret["BITBUCKET_WORKSPACE"], "repositories": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Read-only repositories:", len(rows))


if __name__ == "__main__":
    try:
        main()
    except HTTPError as exc:
        raise SystemExit(f"Bitbucket read failed: HTTP {exc.code}") from None

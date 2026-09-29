"""Preserve fixture evidence and restore actual Java/JS projects to primary 60."""
import json
import shutil
from pathlib import Path

from run import initial_result, render_reports
from seed_manifest import REPOSITORIES, resolve


def main():
    here = Path(__file__).parent
    output = here / "results" / "run-20260929"
    old_manifest = json.loads((here / "manifest.json").read_text(encoding="utf-8"))
    old_report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    snapshot = here / "results" / "legacy-fixture-inclusive-20260929"
    if snapshot.exists():
        raise RuntimeError("Migration snapshot already exists; refuse to overwrite evidence")
    snapshot.mkdir(parents=True)
    shutil.copy2(here / "manifest.json", snapshot / "manifest.json")
    for name in ("results.json", "results.csv", "results.md"):
        shutil.copy2(output / name, snapshot / name)
    fixtures = [row for row in old_manifest["repositories"] if row["source_host"] == "bitbucket.org"]
    (here / "fixtures-manifest.json").write_text(json.dumps({"schema_version": 1, "description": "Supplemental existing Bitbucket integration fixtures; not the primary 60 applications.", "repositories": fixtures}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    supplemental = here / "results" / "bitbucket-fixtures"
    supplemental.mkdir(parents=True, exist_ok=True)
    supplemental_rows = [row for row in old_report["repositories"] if row["source_host"] == "bitbucket.org"]
    (supplemental / "results.json").write_text(json.dumps({"schema_version": 1, "description": "Preserved supplemental Bitbucket evidence, not extra successful applications in the 60-row matrix.", "repositories": supplemental_rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    by_id = {row["id"]: row for row in old_report["repositories"]}
    old_by_repo = {row["repository_url"]: row for row in old_manifest["repositories"]}
    rows = []
    for language in ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby"):
        if language in ("Java", "JavaScript"):
            for entry in REPOSITORIES[language]:
                url = "https://github.com/" + entry[0] + ".git"
                rows.append(old_by_repo.get(url) or resolve((language, entry)))
        else:
            rows.extend(row for row in old_manifest["repositories"] if row["language"] == language)
    (here / "manifest.json").write_text(json.dumps({"schema_version": 1, "description": "60 distinct real code repositories: 3 existing Bitbucket Python projects and 57 public repositories; 10 per language. Code-less/CI-only cloud fixtures are supplemental.", "repositories": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    results = []
    for row in rows:
        result = by_id.get(row["id"])
        preserved = here / ".work" / row["id"] / "result.json"
        if result is None and preserved.exists():
            result = json.loads(preserved.read_text(encoding="utf-8"))
        results.append(result or initial_result(row))
    render_reports(results, output)
    print("Primary:", len(results), "Supplemental:", len(supplemental_rows), "Snapshot:", snapshot)


if __name__ == "__main__":
    main()

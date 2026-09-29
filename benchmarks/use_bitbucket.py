"""Substitute 3 existing Python code projects; preserve exactly 10 per language."""
import json
from pathlib import Path

root = Path(__file__).parent
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
inventory = json.loads((root / "bitbucket-inventory.json").read_text(encoding="utf-8"))
mapping = {
    "Python": [("python-service", "pip", "demo-app", "1.0.0"), ("python-jobs", "pip", "demo-app", "1.0.0"), ("lab-python", "plain", None, None)],
}
by_slug = {row["slug"]: row for row in inventory["repositories"]}
rows = []
for language in ("Java", "JavaScript", "Python", "Rust", "Go", "Ruby"):
    cloud = mapping.get(language, [])
    for slug, build_system, package, version in cloud:
        row = by_slug[slug]
        rows.append({"id": "bitbucket-" + slug, "language": language, "repository_url": row["repository_url"],
                     "release_ref": row["mainbranch"], "commit": row["commit"], "expected_package": package,
                     "expected_version": version, "source_host": "bitbucket.org", "image_kind": "controlled-source-build",
                     "build_system": build_system, "build_link": "benchmark-recipe; not upstream attestation", "resolution_status": "resolved",
                     "expected_identity_scope": "manifest_metadata_only" if slug in {"java-maven-api", "java-maven-orders", "java-gradle-worker", "java-gradle-billing", "npm-frontend", "npm-admin"} else "primary_release_package",
                     "fixture_kind": "existing integration fixture; not production application"})
    candidates = [row for row in manifest["repositories"] if row["language"] == language and row["source_host"] == "github.com"]
    rows.extend(candidates[-(10-len(cloud)):])
manifest["repositories"] = rows
manifest["description"] = "60 distinct pinned code repositories: 3 existing Bitbucket Python projects and 57 public repositories; 10 per language."
(root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(manifest["description"])

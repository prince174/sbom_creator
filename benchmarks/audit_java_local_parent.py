"""Development snapshot audit; regular Git blobs only, no checkout path reads."""
import hashlib
import json
import subprocess
from collections import Counter

from java_local_parent import chain
from run import ROOT


def main():
    index = json.loads((ROOT / "benchmarks/references/build-v1/index.json").read_bytes())
    split = json.loads((ROOT / "benchmarks/direct-evaluation-split-v1.json").read_bytes())
    rows = []
    for project in index["projects"]:
        if project["language"] != "Java" or project["id"] not in split["development"]:
            continue
        repo = ROOT / "benchmarks/.work" / project["id"] / "src"
        def git(*args, repo=repo):
            return subprocess.check_output(["git", *args], cwd=repo, timeout=30)
        entries = git("ls-tree", "-rz", project["commit"]).split(b"\0")
        blobs = {}
        total = 0
        for entry in entries:
            if not entry:
                continue
            metadata, path = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            if mode not in (b"100644", b"100755") or kind != b"blob" or path.split(b"/")[-1] != b"pom.xml":
                continue
            size = int(git("cat-file", "-s", oid.decode()))
            total += size
            if size > 1024 * 1024 or total > 16 * 1024 * 1024 or len(blobs) >= 256:
                raise ValueError("Audit corpus budget exceeded")
            blobs[path.decode()] = git("cat-file", "blob", oid.decode())
        results = [{"path": path, "sha256": hashlib.sha256(raw).hexdigest(), **chain(blobs, path)}
                   for path, raw in sorted(blobs.items())]
        rows.append({"project": project["id"], "commit": project["commit"], "poms": results})
    counts = Counter(p["reason"] for row in rows for p in row["poms"])
    report = {"experiment": "R24", "partition": "development only", "rows": rows,
              "counts": dict(counts), "runtime_changed": False, "holdout_read": False,
              "effective_model_resolved": False, "direct_accuracy": None,
              "limitation": "Literal identities only; no inheritance merge, profiles or direct edges. Includes test/example POMs; not module coverage."}
    (ROOT / "docs/java-local-parent-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"projects": len(rows), "counts": dict(counts)}))


if __name__ == "__main__":
    main()

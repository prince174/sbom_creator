"""Read development Gson source at frozen commit; never read oracle inputs."""
import hashlib
import json
import subprocess

from java_local_parent import chain
from java_profile_impact import audit
from run import ROOT


def main():
    prior = json.loads((ROOT / "docs/java-local-parent-v1.json").read_bytes())
    project = next(p for p in prior["rows"] if p["project"] == "java-gson")
    repo = ROOT / "benchmarks/.work/java-gson/src"
    blobs = {}
    for path in ("pom.xml", "gson/pom.xml"):
        raw = subprocess.check_output(["git", "show", project["commit"] + ":" + path], cwd=repo, timeout=30)
        expected = next(p["sha256"] for p in project["poms"] if p["path"] == path)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Source differs from R24")
        blobs[path] = raw
    local = chain(blobs, "gson/pom.xml")
    if local["status"] != "LOCAL_CHAIN_FOUND":
        raise ValueError("Local parent chain unavailable")
    report = {"experiment": "R25", "project": "java-gson", "commit": project["commit"],
              "chain": local, "audit": audit(list(blobs.values())),
              "partition": "development", "runtime_changed": False, "direct_accuracy": None,
              "oracle_read": False, "source_sha256": {p: hashlib.sha256(b).hexdigest() for p, b in blobs.items()}}
    (ROOT / "docs/gson-profile-impact-v1.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

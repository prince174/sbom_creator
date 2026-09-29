"""Package an audited test run and verify every exported byte and wheel module."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package(report_dir, version, receipt):
    report_bytes = (report_dir / "results.json").read_bytes()
    report = json.loads(report_bytes)
    audit = json.loads((report_dir / "audit-final.json").read_bytes())
    assert audit["audit_passed"] and audit["completed_rows_audited"] == 60
    assert audit["snapshot_sha256"] == digest(report_bytes)
    wheel = ROOT / "dist" / f"sbom_creator-{version}-py3-none-any.whl"
    modules = {}
    with zipfile.ZipFile(wheel) as archive:
        assert archive.testzip() is None
        for source in sorted((ROOT / "src/sbom_creator").glob("*.py")):
            name = source.relative_to(ROOT / "src").as_posix()
            assert archive.read(name) == source.read_bytes(), name
            modules[name] = digest(archive.read(name))
        schemas = [name for name in archive.namelist() if "/schemas/" in name and name.endswith(".json")]
        assert len(schemas) == 4
        for name in schemas:
            assert archive.read(name) == (ROOT / "src" / name).read_bytes()
    destination = ROOT / "dist" / f"sbom-creator-{version}-60-cyclonedx.zip"
    entries = {}
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        def add(name, data):
            assert name not in entries
            archive.writestr(name, data)
            entries[name] = digest(data)

        for name in ("results.json", "results.csv", "results.md", "audit-final.json"):
            add("reports/" + name, (report_dir / name).read_bytes())
        for row in report["repositories"]:
            assert row["status"] == "completed_rules" and row["cyclonedx_valid"]
            directory = Path(row["analysis_directory"])
            summary = json.loads((directory / "summary.json").read_bytes())
            provenance = json.loads((directory / "provenance.json").read_bytes())
            assert summary["payload_verification"] == "performed"
            assert summary["policy_version"] == "image-evidence-and-payload-v3"
            assert isinstance(provenance["image"]["payload_evidence"], dict)
            final = (directory / "final.cdx.json").read_bytes()
            assert digest(final) == row["final_sha256"]
            for name in ("final.cdx.json", "summary.json", "coverage.json", "review.json", "provenance.json"):
                add(row["id"] + "/" + name, (directory / name).read_bytes())
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
        assert set(archive.namelist()) == set(entries)
        assert all(digest(archive.read(name)) == expected for name, expected in entries.items())
    image = subprocess.check_output(["docker", "image", "inspect", f"sbom-creator:{version}",
                                     "--format", "{{.Id}}"], text=True).strip()
    http_path = ROOT / "docs/verification-http-v3-release.json"
    http = json.loads(http_path.read_bytes())
    assert http["passed"] and http["base_service_image_id"] == image
    installed = json.loads((ROOT / "docs/verification-installed-linux-rules-v3-final.json").read_bytes())
    assert installed["status"] == "passed" and installed["host_module_hashes_match"]
    for name, evidence in installed["runtime_modules"].items():
        source = ROOT / "src" / (name.replace(".", "/") + ".py")
        if name == "sbom_creator":
            source = ROOT / "src/sbom_creator/__init__.py"
        assert evidence["sha256"] == digest(source.read_bytes())
    result = {"version": version, "passed": True, "docker_image_id": image,
        "http_evidence_sha256": digest(http_path.read_bytes()), "installed_modules_verified": len(installed["runtime_modules"]),
        "report_sha256": digest(report_bytes), "audit_sha256": digest((report_dir / "audit-final.json").read_bytes()),
        "wheel": str(wheel), "wheel_sha256": digest(wheel.read_bytes()),
        "wheel_modules_match_source": modules, "wheel_schema_count": len(schemas),
        "archive": str(destination), "archive_sha256": digest(destination.read_bytes()),
        "archive_bytes": destination.stat().st_size, "final_sboms": 60, "crc_valid": True,
        "entry_sha256": entries,
        "scope": "Controlled test results; raw Syft catalogs and decisions remain in local analysis directories."}
    with receipt.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return {key: value for key, value in result.items() if key not in {"entry_sha256", "wheel_modules_match_source"}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.report_dir, args.version, args.receipt), indent=2))

"""Resolve only literal local parent identities in an immutable Git blob map.

No filesystem traversal, model merge, profile activation or direct-edge inference.
"""
import posixpath
import xml.etree.ElementTree as ET

from audit_maven_declarations import declarations

NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def chain(blobs, start, limit=16):
    current = start
    seen = []
    while True:
        if current in seen:
            return {"status": "UNKNOWN", "reason": "cycle", "chain": seen}
        if len(seen) >= limit:
            return {"status": "UNKNOWN", "reason": "depth_limit", "chain": seen}
        raw = blobs.get(current)
        if raw is None:
            return {"status": "UNKNOWN", "reason": "missing_local_pom", "chain": seen}
        try:
            declarations(raw)
            root = ET.fromstring(raw)
        except (ValueError, ET.ParseError):
            return {"status": "UNKNOWN", "reason": "invalid_pom", "chain": seen}
        seen.append(current)
        parent = root.find("m:parent", NS)
        if parent is None:
            return {"status": "LOCAL_CHAIN_FOUND", "reason": "identity_only", "chain": seen}
        relative = parent.find("m:relativePath", NS)
        path = "../pom.xml" if relative is None else (relative.text or "").strip()
        if not path:
            return {"status": "UNKNOWN", "reason": "local_lookup_disabled", "chain": seen}
        if any(c in path for c in ("\\", ":", "$", "\x00")) or path.startswith("/"):
            return {"status": "UNKNOWN", "reason": "unsupported_path", "chain": seen}
        target = posixpath.normpath(posixpath.join(posixpath.dirname(current), path))
        if target == ".." or target.startswith("../"):
            return {"status": "UNKNOWN", "reason": "outside_repository", "chain": seen}
        if target not in blobs:
            target = posixpath.join(target, "pom.xml")
        candidate = blobs.get(target)
        if candidate is None:
            return {"status": "UNKNOWN", "reason": "missing_local_parent", "chain": seen}
        try:
            declarations(candidate)
            candidate_root = ET.fromstring(candidate)
        except (ValueError, ET.ParseError):
            return {"status": "UNKNOWN", "reason": "invalid_parent", "chain": seen}
        expected = [(parent.findtext("m:" + k, "", NS)).strip() for k in ("groupId", "artifactId", "version")]
        actual = [(candidate_root.findtext("m:" + k, "", NS)).strip() for k in ("groupId", "artifactId", "version")]
        if any(not v or "${" in v for v in expected + actual) or expected != actual:
            return {"status": "UNKNOWN", "reason": "unresolved_or_mismatched_identity", "chain": seen}
        current = target

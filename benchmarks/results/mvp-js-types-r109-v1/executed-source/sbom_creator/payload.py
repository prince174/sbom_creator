"""Bounded passive payload corroboration; never extract or execute image files.

The pinned Syft final-filesystem inventory supplies paths and layer identities.
Only selected RECORD/JAR data is read from those layers. Evidence establishes
some package payload, not completeness, importability, reachability or use.
"""
from __future__ import annotations

import base64
import bisect
import csv
import hashlib
import io
import json
import posixpath
import re
import tarfile
import zipfile
from contextlib import ExitStack

from packageurl import PackageURL

SUPPORTED = {"python-installed-package-cataloger", "javascript-package-cataloger",
             "ruby-installed-gemspec-cataloger", "java-archive-cataloger",
             "go-module-binary-cataloger", "cargo-auditable-binary-cataloger"}
MAX_READ = 32 * 1024 * 1024


def path(value):
    return posixpath.normpath("/" + str(value).replace("\\", "/").lstrip("/"))


class ImageFiles:
    """Read only the layer containing a file in Syft's squashed inventory."""
    def __init__(self, archive, document):
        self.stack = ExitStack()
        try:
            self.outer = self.stack.enter_context(tarfile.open(archive, "r:*"))  # noqa: SIM115 -- owned by ExitStack
            manifest = json.loads(self._outer_read("manifest.json", 4 * 1024 * 1024))[0]
            config = json.loads(self._outer_read(manifest["Config"], 4 * 1024 * 1024))
            self.layers = dict(zip(config["rootfs"]["diff_ids"], manifest["Layers"], strict=True))
            self.opened = {}
            self.files = {path(f["location"]["path"]): f for f in document.get("files", [])}
            self.paths = sorted(self.files)
        except Exception:
            self.stack.close()
            raise

    def close(self):
        self.stack.close()

    def _outer_read(self, name, limit):
        member = self.outer.getmember(name)
        if not member.isfile() or member.size > limit:
            raise ValueError("Invalid or oversized image metadata")
        with self.outer.extractfile(member) as stream:
            return stream.read(limit + 1)

    def regular(self, name):
        entry = self.files.get(path(name), {})
        meta = entry.get("metadata", {})
        return meta.get("type") == "RegularFile" and meta.get("size", 0) > 0

    def under(self, prefix):
        prefix = path(prefix).rstrip("/") + "/"
        start = bisect.bisect_left(self.paths, prefix)
        for index in range(start, len(self.paths)):
            name = self.paths[index]
            if not name.startswith(prefix):
                break
            if self.regular(name):
                yield name

    def read(self, name, limit=MAX_READ):
        name = path(name)
        if not self.regular(name):
            return None
        entry = self.files[name]
        if entry["metadata"]["size"] > limit:
            return None
        layer = entry["location"].get("layerID")
        if layer not in self.layers:
            return None
        if layer not in self.opened:
            member = self.outer.getmember(self.layers[layer])
            if not member.isfile():
                raise ValueError("Image layer must be a regular archive member")
            stream = self.stack.enter_context(self.outer.extractfile(member))
            archive = self.stack.enter_context(tarfile.open(fileobj=stream, mode="r:*"))  # noqa: SIM115 -- owned by ExitStack
            members = {}
            for count, item in enumerate(archive):
                if count >= 300_000:
                    raise ValueError("Image layer file-index limit exceeded")
                members[path(item.name)] = item
            self.opened[layer] = archive, members
        archive, members = self.opened[layer]
        member = members.get(name)
        if member is None or not member.isfile() or member.size > limit:
            return None
        with archive.extractfile(member) as stream:
            data = stream.read(limit + 1)
        return data if len(data) <= limit else None


class SyftFiles(ImageFiles):
    """Read bounded base64 contents from the same squashed Syft scan."""
    def __init__(self, document):
        self.files = {}
        for entry in document.get("files", []):
            name = path(entry["location"]["path"])
            if name in self.files:
                raise ValueError("Ambiguous final filesystem path")
            self.files[name] = entry
        self.paths = sorted(self.files)

    def close(self):
        pass

    def read(self, name, limit=MAX_READ):
        name = path(name)
        if not self.regular(name):
            return None
        entry = self.files[name]
        content = entry.get("contents")
        if (entry["metadata"]["size"] > limit or not isinstance(content, str)
                or len(content) > 4 * ((limit + 2) // 3)):
            return None
        raw = base64.b64decode(content, validate=True)
        if len(raw) != entry["metadata"]["size"]:
            raise ValueError("Syft file content size mismatch")
        return raw if len(raw) <= limit else None


def _python(artifact, files):
    for location in artifact.get("locations", []):
        metadata = path(location.get("path", ""))
        directory = posixpath.dirname(metadata)
        if not directory.endswith(".dist-info"):
            continue
        record = files.read(directory + "/RECORD", 1024 * 1024)
        if record is None:
            continue
        for row in csv.reader(io.StringIO(record.decode("utf-8"))):
            if not row:
                continue
            target = path(posixpath.join(posixpath.dirname(directory), row[0]))
            if target.startswith(directory + "/"):
                continue
            if target.endswith((".py", ".pyc", ".so", ".pyd")) and files.regular(target):
                return target
    return None


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate type-surface manifest member")
        result[key] = value
    return result


def _javascript_types(artifact, files, package_roots, directory, raw):
    """Confirm a declared delivered file, not executable JavaScript or valid types."""
    if raw is None:
        return None
    manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members)
    if not isinstance(manifest, dict):
        return None
    fields = [field for field in ("types", "typings") if field in manifest]
    if not fields:
        return None
    identity = PackageURL.from_string(artifact.get("purl", ""))
    name = f"{identity.namespace}/{identity.name}" if identity.namespace else identity.name
    if (identity.type != "npm" or manifest.get("name") != name
            or not isinstance(manifest.get("version"), str)
            or manifest["version"] != identity.version
            or artifact.get("version") != identity.version):
        return None
    targets = set()
    for field in fields:
        value = manifest[field]
        if (not isinstance(value, str) or not value or len(value) > 4096
                or value.startswith("/") or any(c in value for c in ("\\", ":", "?", "#"))
                or any(ord(c) < 32 or ord(c) == 127 for c in value)
                or ".." in value.split("/") or not value.endswith(".d.ts")):
            return None
        target = path(posixpath.join(directory, value))
        prefix = directory.rstrip("/") + "/"
        owner_entry = files.files.get(directory)
        if owner_entry is not None and owner_entry.get("metadata", {}).get("type") != "Directory":
            return None
        if (not target.startswith(prefix) or "node_modules" in target[len(prefix):].split("/")[:-1]
                or any(target.startswith(other.rstrip("/") + "/") for other in package_roots
                       if other != directory and other.startswith(prefix))):
            return None
        parent = posixpath.dirname(target)
        while parent != directory and parent.startswith(prefix):
            entry = files.files.get(parent)
            if entry is not None and entry.get("metadata", {}).get("type") != "Directory":
                return None
            parent = posixpath.dirname(parent)
        targets.add(target)
    if len(targets) != 1:
        return None
    target = next(iter(targets))
    if not files.regular(target):
        return None
    return target, {"payload_kind": "declared_type_surface", "declaration_fields": fields,
                    "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                    "scope": "Declared nonempty type-surface file present in the final image; "
                             "JavaScript execution, type validity and file integrity not established"}


def _javascript(artifact, files, package_roots):
    for location in artifact.get("locations", []):
        manifest = path(location.get("path", ""))
        if not manifest.endswith("/package.json"):
            continue
        directory = posixpath.dirname(manifest)
        # Data-only packages can expose JSON through main or the conventional
        # index entry when main is absent. Do not require JavaScript code.
        raw = files.read(manifest, 1024 * 1024)
        manifest_data = json.loads(raw) if raw else None
        if manifest_data is not None and not isinstance(manifest_data, dict):
            continue
        entry = manifest_data.get("main", "index") if manifest_data is not None else None
        if isinstance(entry, str) and entry:
            target = path(posixpath.join(directory, entry))
            if target.startswith(directory + "/") and target != manifest:
                for candidate in (target, target + ".js", target + ".json"):
                    nested_owner = any(candidate.startswith(other + "/") for other in package_roots
                                       if other != directory and other.startswith(directory + "/"))
                    if not nested_owner and files.regular(candidate):
                        return candidate
        for target in files.under(directory):
            if "/node_modules/" in target[len(directory) + 1:] or target.endswith(".d.ts"):
                continue
            if any(target.startswith(other + "/") for other in package_roots
                   if other != directory and other.startswith(directory + "/")):
                continue
            if target.endswith((".js", ".mjs", ".cjs", ".ts", ".node", ".wasm")):
                return target
        declared_types = _javascript_types(artifact, files, package_roots, directory, raw)
        if declared_types is not None:
            return declared_types
    return None


def _ruby(artifact, files):
    for location in artifact.get("locations", []):
        manifest = path(location.get("path", ""))
        if "/specifications/" not in manifest:
            continue
        home = manifest.split("/specifications/", 1)[0]
        gem = posixpath.basename(manifest).removesuffix(".gemspec")
        for target in files.under(home + "/gems/" + gem):
            if target.endswith((".rb", ".so", ".bundle")):
                return target
        if "/specifications/default/" in manifest and "/gems/" in home:
            standard = home.split("/gems/", 1)[0] + "/" + posixpath.basename(home)
            for name in artifact.get("metadata", {}).get("files", []):
                target = path(standard + "/" + name)
                if target.startswith(standard + "/") and target.endswith((".rb", ".so")) and files.regular(target):
                    return target
                # Default native extensions live in Ruby's immediate platform
                # directory, not directly in its versioned standard library.
                if isinstance(name, str) and name.endswith(".so") and not name.startswith("/") and ".." not in name.split("/"):
                    for candidate in files.under(standard):
                        platform, separator, relative = candidate[len(standard) + 1:].partition("/")
                        if (separator and relative == name
                                and re.fullmatch(r"(?:x86_64|aarch64|arm\w*|i[3-6]86|ppc64le|s390x|riscv64)-linux(?:-\w+)?", platform)):
                            return candidate
    return None


def _java(artifact, files):
    for location in artifact.get("locations", []):
        outer = path(location.get("path", ""))
        data = files.read(outer)
        if data is None:
            continue
        virtual = artifact.get("metadata", {}).get("virtualPath", outer)
        if not virtual.startswith(outer):
            continue
        nested = virtual[len(outer):].lstrip(":").split(":") if virtual != outer else []
        if len(nested) > 8:
            continue
        for inner in nested:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                member = archive.getinfo(inner.lstrip("/"))
                if member.file_size > MAX_READ:
                    return None
                data = archive.read(member)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 100_000:
                continue
            for member in archive.infolist():
                if member.filename.endswith(".class") and member.file_size >= 4:
                    with archive.open(member) as stream:
                        if stream.read(4) == b"\xca\xfe\xba\xbe":
                            return virtual + ":" + member.filename
    return None


def collect(document, archive=None, *, files_factory=None, java_witness=None, close_files=True):
    evidence = {}
    if not any(a.get("foundBy") in SUPPORTED for a in document["artifacts"]):
        return evidence
    files = (files_factory(archive, document) if files_factory is not None else
             ImageFiles(archive, document) if archive is not None else SyftFiles(document))
    package_roots = {posixpath.dirname(path(loc.get("path", ""))) for a in document["artifacts"]
                     if a.get("foundBy") == "javascript-package-cataloger" for loc in a.get("locations", [])}
    try:
        for artifact in document["artifacts"]:
            cataloger = artifact.get("foundBy")
            if cataloger not in SUPPORTED:
                continue
            error = None
            detail = {}
            try:
                if cataloger == "python-installed-package-cataloger":
                    observed = _python(artifact, files)
                elif cataloger == "javascript-package-cataloger":
                    observed = _javascript(artifact, files, package_roots)
                    if isinstance(observed, tuple):
                        observed, detail = observed
                elif cataloger == "ruby-installed-gemspec-cataloger":
                    observed = _ruby(artifact, files)
                elif cataloger == "java-archive-cataloger":
                    observed = java_witness(artifact, files) if java_witness is not None else _java(artifact, files)
                else:
                    observed = next((path(loc["path"]) for loc in artifact.get("locations", [])
                                     if files.regular(loc.get("path", ""))), None)
            except (ValueError, KeyError, OSError, UnicodeError, csv.Error, zipfile.BadZipFile, RuntimeError) as exc:
                observed, error = None, type(exc).__name__
            evidence[artifact["id"]] = {"status": "confirmed" if observed else "unconfirmed",
                "path": observed, "error_type": error,
                "method": ("pinned-syft-final-files-plus-bounded-archive-read-v1" if archive is not None
                           else "pinned-syft-final-files-plus-bounded-content-v2"),
                "scope": "Some payload present; completeness and runtime use not established"}
            evidence[artifact["id"]].update(detail)
    finally:
        if close_files:
            files.close()
    return evidence

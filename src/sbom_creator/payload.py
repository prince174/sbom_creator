"""Bounded passive payload corroboration; never extract or execute image files.

The pinned Syft final-filesystem inventory supplies paths and layer identities.
Only selected RECORD/JAR data is read from those layers. Evidence establishes
some package payload, not completeness, importability, reachability or use.
"""
from __future__ import annotations

import bisect
import csv
import io
import json
import posixpath
import re
import tarfile
import zipfile
from contextlib import ExitStack

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


def _javascript(artifact, files, package_roots):
    for location in artifact.get("locations", []):
        manifest = path(location.get("path", ""))
        if not manifest.endswith("/package.json"):
            continue
        directory = posixpath.dirname(manifest)
        # Data-only packages (for example SPDX tables) can expose JSON through
        # main. Confirm that exact entry point instead of requiring JavaScript.
        raw = files.read(manifest, 1024 * 1024)
        entry = json.loads(raw).get("main") if raw else None
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


def collect(document, archive):
    evidence = {}
    if not any(a.get("foundBy") in SUPPORTED for a in document["artifacts"]):
        return evidence
    files = ImageFiles(archive, document)
    package_roots = {posixpath.dirname(path(loc.get("path", ""))) for a in document["artifacts"]
                     if a.get("foundBy") == "javascript-package-cataloger" for loc in a.get("locations", [])}
    try:
        for artifact in document["artifacts"]:
            cataloger = artifact.get("foundBy")
            if cataloger not in SUPPORTED:
                continue
            error = None
            try:
                if cataloger == "python-installed-package-cataloger":
                    observed = _python(artifact, files)
                elif cataloger == "javascript-package-cataloger":
                    observed = _javascript(artifact, files, package_roots)
                elif cataloger == "ruby-installed-gemspec-cataloger":
                    observed = _ruby(artifact, files)
                elif cataloger == "java-archive-cataloger":
                    observed = _java(artifact, files)
                else:
                    observed = next((path(loc["path"]) for loc in artifact.get("locations", [])
                                     if files.regular(loc.get("path", ""))), None)
            except (ValueError, KeyError, OSError, UnicodeError, csv.Error, zipfile.BadZipFile, RuntimeError) as exc:
                observed, error = None, type(exc).__name__
            evidence[artifact["id"]] = {"status": "confirmed" if observed else "unconfirmed",
                "path": observed, "error_type": error,
                "method": "pinned-syft-final-files-plus-bounded-archive-read-v1",
                "scope": "Some payload present; completeness and runtime use not established"}
    finally:
        files.close()
    return evidence

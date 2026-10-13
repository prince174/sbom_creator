"""Experimental bounded loader/budget around frozen Python P1+guard."""
import hashlib
import os
import stat
import tomllib
from pathlib import Path

from python_p1_guard import classify as guarded

MANIFEST_BYTES = 1024 * 1024
MAX_NODES = 250000
MAX_TEXT = 16 * 1024 * 1024
MAX_DEPTH = 64


def within_budget(value, max_nodes=MAX_NODES, max_text=MAX_TEXT, max_depth=MAX_DEPTH):
    stack = [(value, 0)]
    nodes = chars = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            return False
        if isinstance(item, str):
            chars += len(item)
        elif isinstance(item, dict):
            # Bound queue size before allocation; keys count towards total text.
            if len(item) * 2 + nodes + len(stack) > max_nodes:
                return False
            for key, child in item.items():
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) + nodes + len(stack) > max_nodes:
                return False
            stack.extend((child, depth + 1) for child in item)
        if chars > max_text:
            return False
    return True


def unknown(reason):
    return {"status": "UNKNOWN", "reason": reason, "edges": [], "coverage": None,
            "build_usage_proven": False}


def load_manifest(checkout):
    path = Path(checkout).resolve() / "pyproject.toml"
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_size > MANIFEST_BYTES
                or getattr(before, "st_file_attributes", 0) & 0x400):
            return unknown("unsafe_or_oversized_manifest")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                return unknown("manifest_changed_before_read")
            raw = stream.read(MANIFEST_BYTES + 1)
        if len(raw) > MANIFEST_BYTES:
            return unknown("unsafe_or_oversized_manifest")
        document = tomllib.loads(raw.decode("utf-8"))
        if not within_budget(document):
            return unknown("manifest_budget_exceeded")
        return {"status": "available", "sha256": hashlib.sha256(raw).hexdigest(), "document": document}
    except FileNotFoundError:
        return {"status": "not-applicable", "reason": "no_root_pyproject"}
    except (OSError, ValueError, TypeError, RecursionError):
        return unknown("unreadable_or_invalid_manifest")


def classify(source, image):
    if not within_budget([source, image]):
        return unknown("classification_input_budget_exceeded")
    return guarded(source, image)

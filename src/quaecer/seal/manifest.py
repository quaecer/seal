# SPDX-License-Identifier: Apache-2.0
"""Create and verify canonical SHA-256 manifests for regular files."""

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypedDict

_FORMAT = "seal-manifest@1"
_MAX_EXACT_INT = 2**53 - 1
_HASH = re.compile(r"[a-f0-9]{64}")


class Entry(TypedDict):
    path: str
    size: int
    sha256: str


class Inventory(TypedDict):
    format: str
    files: list[Entry]


class Manifest(Inventory):
    commitment: str


def _canonical(value: Inventory | Manifest) -> bytes:
    # Fixed ASCII field names, scalar strings and safe nonnegative integers
    # form a restricted domain in which these settings produce JCS bytes.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def _parts(path: str) -> list[str]:
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or "\\" in path or "\0" in path:
        raise ValueError("paths must be relative POSIX file names")
    path.encode("utf-8")
    return parts


@contextmanager
def _directory(path: str | Path, parent: int | None = None) -> Iterator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _file(root: int, label: str) -> Entry:
    parts = _parts(label)
    directory = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_EXACT_INT:
                raise ValueError("only regular files with representable sizes may be sealed")
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(fd, "rb", closefd=False) as stream:
                while block := stream.read(128 * 1024):
                    size += len(block)
                    digest.update(block)
            after = os.fstat(fd)
            unchanged = (
                before.st_size == after.st_size == size
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns
            )
            if not unchanged:
                raise ValueError("file changed while being read")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    return {"path": label, "size": size, "sha256": digest.hexdigest()}


def freeze(root: Path, paths: Iterable[str]) -> Manifest:
    """Read each relative regular file and return its ordered manifest."""
    names = sorted(paths)
    if not names or len(set(names)) != len(names):
        raise ValueError("a manifest needs nonempty, distinct paths")
    with _directory(root) as descriptor:
        inventory: Inventory = {
            "format": _FORMAT,
            "files": [_file(descriptor, name) for name in names],
        }
    return {**inventory, "commitment": hashlib.sha256(_canonical(inventory)).hexdigest()}


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate JSON member")
    return fields


def read_manifest(raw: bytes) -> Manifest:
    """Validate a manifest and its commitment independently of local files."""
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    if not isinstance(doc, dict) or doc.keys() != {"format", "files", "commitment"}:
        raise ValueError("invalid manifest members")
    if doc["format"] != _FORMAT or not isinstance(doc["files"], list) or not doc["files"]:
        raise ValueError("invalid manifest format or empty file list")
    entries: list[Entry] = []
    last = ""
    for entry in doc["files"]:
        if not isinstance(entry, dict) or entry.keys() != {"path", "size", "sha256"}:
            raise ValueError("invalid file entry")
        name, size, digest = entry["path"], entry["size"], entry["sha256"]
        if not isinstance(name, str) or name <= last:
            raise ValueError("file paths must be sorted and unique")
        _parts(name)
        if type(size) is not int or not 0 <= size <= _MAX_EXACT_INT:
            raise ValueError("invalid file size")
        if not isinstance(digest, str) or not _HASH.fullmatch(digest):
            raise ValueError("invalid file digest")
        entries.append({"path": name, "size": size, "sha256": digest})
        last = name
    inventory: Inventory = {"format": _FORMAT, "files": entries}
    commitment = hashlib.sha256(_canonical(inventory)).hexdigest()
    if doc["commitment"] != commitment:
        raise ValueError("manifest commitment mismatch")
    return {**inventory, "commitment": commitment}


def canonical_manifest(manifest: Manifest) -> bytes:
    """Encode the checked manifest as canonical UTF-8 JSON."""
    return _canonical(manifest)


def verify(root: Path, raw: bytes) -> Manifest:
    """Reject if the commitment, byte counts or file hashes fail verification."""
    manifest = read_manifest(raw)
    with _directory(root) as descriptor:
        for entry in manifest["files"]:
            if _file(descriptor, entry["path"]) != entry:
                raise ValueError(f"file does not match manifest: {entry['path']!r}")
    return manifest

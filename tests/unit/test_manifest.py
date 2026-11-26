# SPDX-License-Identifier: Apache-2.0
"""Verify canonical bytes, file integrity and rejection of path aliases."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from quaecer.seal.manifest import canonical_manifest, freeze, read_manifest, verify


class ManifestTest(unittest.TestCase):
    def test_commitment_and_canonical_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "é.txt").write_bytes(b"")
            (root / "a.txt").write_bytes(b"abc")
            manifest = freeze(root, ["é.txt", "a.txt"])
            body = (
                '{"files":[{"path":"a.txt","sha256":"'
                + hashlib.sha256(b"abc").hexdigest()
                + '","size":3},{"path":"é.txt","sha256":"'
                + hashlib.sha256(b"").hexdigest()
                + '","size":0}],"format":"seal-manifest@1"}'
            ).encode()
            self.assertEqual(manifest["commitment"], hashlib.sha256(body).hexdigest())
            self.assertEqual(verify(root, canonical_manifest(manifest)), manifest)
            self.assertEqual(freeze(root, ["a.txt", "é.txt"]), manifest)

    def test_content_and_metadata_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"a")
            manifest = freeze(root, ["a"])
            (root / "a").write_bytes(b"z")
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify(root, canonical_manifest(manifest))
            changed = dict(manifest, commitment="0" * 64)
            with self.assertRaisesRegex(ValueError, "commitment mismatch"):
                read_manifest(json.dumps(changed).encode())

    def test_rejects_aliases_and_non_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "subdir").mkdir()
            (root / "subdir" / "a").write_bytes(b"")
            (root / "link").symlink_to(root / "subdir", target_is_directory=True)
            (root / "filelink").symlink_to(root / "subdir" / "a")
            for path in ("../outside", "./subdir/a", "subdir//a", "/subdir/a", "dir\\file"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    freeze(root, [path])
            for path in ("link/a", "filelink", "missing"):
                with self.subTest(path=path), self.assertRaises(OSError):
                    freeze(root, [path])
            with self.assertRaises((OSError, ValueError)):
                freeze(root, ["subdir"])
            with self.assertRaises(ValueError):
                freeze(root, ["subdir/a", "subdir/a"])

    def test_rejects_duplicate_members(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            read_manifest(b'{"format":"seal-manifest@1","format":"seal-manifest@1"}')

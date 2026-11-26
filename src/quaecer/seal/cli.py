# SPDX-License-Identifier: Apache-2.0
"""Create or verify a local artifact manifest."""

import argparse
import os
import tempfile
from pathlib import Path

from .manifest import canonical_manifest, freeze, verify


def _write_new(path: Path, content: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".seal-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink()


def main() -> int:
    """Run an offline freeze or verification command."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    create = commands.add_parser("freeze")
    create.add_argument("paths", nargs="+")
    create.add_argument("--out", required=True, type=Path)
    create.add_argument("--root", type=Path, default=Path("."))
    check = commands.add_parser("verify")
    check.add_argument("manifest", type=Path)
    check.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        if args.operation == "freeze":
            manifest = freeze(args.root, args.paths)
            _write_new(args.out, canonical_manifest(manifest))
        else:
            manifest = verify(args.root, args.manifest.read_bytes())
    except (OSError, ValueError, RecursionError) as error:
        parser.exit(2, f"seal: {error}\n")
    print(manifest["commitment"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

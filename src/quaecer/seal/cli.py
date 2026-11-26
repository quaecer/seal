# SPDX-License-Identifier: Apache-2.0
"""Create or verify a local artifact manifest."""

import argparse
import os
import tempfile
from pathlib import Path
from subprocess import TimeoutExpired

from .manifest import canonical_manifest, freeze, read_manifest, verify
from .timestamp import timestamp_request, verify_timestamp


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


def _trust_options(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--ca", type=Path, required=required)
    parser.add_argument("--chain", type=Path)
    parser.add_argument("--query", type=Path)


def _check_timestamp(commitment: str, path: Path, args: argparse.Namespace) -> bytes:
    if args.ca is None:
        raise ValueError("timestamp verification needs an explicit --ca file")
    with path.open("rb") as stream:
        response = stream.read(2 * 1024 * 1024 + 1)
    query = None
    if args.query is not None:
        with args.query.open("rb") as stream:
            query = stream.read(2 * 1024 * 1024 + 1)
    verify_timestamp(commitment, response, ca=args.ca, query=query, chain=args.chain)
    return response


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
    check.add_argument("--timestamp", type=Path)
    _trust_options(check, required=False)
    request = commands.add_parser("timestamp-request")
    request.add_argument("manifest", type=Path)
    request.add_argument("--out", required=True, type=Path)
    stamp = commands.add_parser("stamp")
    stamp.add_argument("manifest", type=Path)
    stamp.add_argument("response", type=Path)
    stamp.add_argument("--out", required=True, type=Path)
    _trust_options(stamp, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "freeze":
            manifest = freeze(args.root, args.paths)
            _write_new(args.out, canonical_manifest(manifest))
        elif args.operation == "verify":
            manifest = verify(args.root, args.manifest.read_bytes())
            if args.timestamp is not None:
                _check_timestamp(manifest["commitment"], args.timestamp, args)
            elif args.ca is not None or args.chain is not None or args.query is not None:
                raise ValueError("timestamp trust options require --timestamp")
        else:
            manifest = read_manifest(args.manifest.read_bytes())
            commitment = manifest["commitment"]
            if args.operation == "timestamp-request":
                _write_new(args.out, timestamp_request(commitment))
            else:
                _write_new(args.out, _check_timestamp(commitment, args.response, args))
    except (OSError, ValueError, RecursionError, TimeoutExpired) as error:
        parser.exit(2, f"seal: {error}\n")
    print(manifest["commitment"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

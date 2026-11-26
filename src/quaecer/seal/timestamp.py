# SPDX-License-Identifier: Apache-2.0
"""Create and verify detached RFC 3161 artifacts through local OpenSSL."""

import re
import subprocess
import tempfile
from pathlib import Path

_MAX_RESPONSE = 2 * 1024 * 1024


def _openssl(arguments: list[str]) -> bytes:
    completed = subprocess.run(
        ["openssl", "ts", *arguments],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode:
        raise ValueError("OpenSSL rejected the timestamp operation")
    return completed.stdout


def timestamp_request(commitment: str, *, nonce: bool = True) -> bytes:
    """Return a DER request for the exact SHA-256 commitment."""
    if not re.fullmatch(r"[a-f0-9]{64}", commitment):
        raise ValueError("invalid timestamp commitment")
    arguments = ["-query", "-sha256", "-digest", commitment, "-cert"]
    if not nonce:
        arguments.append("-no_nonce")
    return _openssl(arguments)


def verify_timestamp(
    commitment: str,
    response: bytes,
    *,
    ca: Path,
    query: bytes | None = None,
    chain: Path | None = None,
) -> None:
    """Check the SHA-256 imprint, TSA signature, explicit trust and optional nonce."""
    if not response or len(response) > _MAX_RESPONSE:
        raise ValueError("invalid timestamp response size")
    if query is not None and (not query or len(query) > _MAX_RESPONSE):
        raise ValueError("invalid timestamp request size")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        reply = root / "response.tsr"
        reply.write_bytes(response)
        ca = ca.resolve(strict=True)
        if not ca.is_file():
            raise ValueError("timestamp trust requires a CA file")
        trust = root / "trust.pem"
        trust.write_bytes(ca.read_bytes())
        arguments = ["-verify", "-CAfile", str(trust), "-in", str(reply)]
        if chain is not None:
            chain_file = root / "chain.pem"
            chain_file.write_bytes(chain.read_bytes())
            arguments.extend(["-untrusted", str(chain_file)])
        # A fresh nonce-free request pins the message-imprint algorithm as well as the digest.
        request = root / "expected.tsq"
        request.write_bytes(timestamp_request(commitment, nonce=False))
        _openssl([*arguments, "-queryfile", str(request)])
        if query is not None:
            request.write_bytes(query)
            _openssl([*arguments, "-queryfile", str(request)])

# SPDX-License-Identifier: Apache-2.0
"""Check RFC 3161 verification against a locally issued token."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from quaecer.seal.timestamp import timestamp_request, verify_timestamp


@unittest.skipUnless(shutil.which("openssl"), "optional OpenSSL executable")
class TimestampTest(unittest.TestCase):
    def test_commitment_trust_and_nonce(self) -> None:
        digest = "ab" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca = root / "cert.pem"
            key = root / "private.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Local test only",
                    "-keyout",
                    str(key),
                    "-out",
                    str(ca),
                    "-addext",
                    "extendedKeyUsage=critical,timeStamping",
                ],
                capture_output=True,
                check=True,
            )
            serial = root / "serial"
            serial.write_text("01\n")
            config = root / "tsa.cnf"
            config.write_text(
                f"[tsa]\nserial={serial}\nsigner_cert={ca}\nsigner_key={key}\n"
                "signer_digest=sha256\ndefault_policy=1.2.3.4.5\ndigests=sha256\n"
                "ess_cert_id_alg=sha256\n"
            )
            raw_query = timestamp_request(digest)
            request = root / "query.tsq"
            request.write_bytes(raw_query)
            reply = subprocess.run(
                [
                    "openssl",
                    "ts",
                    "-reply",
                    "-config",
                    str(config),
                    "-section",
                    "tsa",
                    "-queryfile",
                    str(request),
                ],
                capture_output=True,
                check=True,
            ).stdout
            verify_timestamp(digest, reply, ca=ca, query=raw_query)
            with self.assertRaises(ValueError):
                verify_timestamp("cd" * 32, reply, ca=ca, query=raw_query)
            with self.assertRaises(ValueError):
                verify_timestamp(digest, reply, ca=ca, query=timestamp_request(digest))
            with self.assertRaises(ValueError):
                verify_timestamp(digest, reply[:-1], ca=ca)

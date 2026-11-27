# Seal

Create a fixed inventory of regular files, then verify their exact bytes.

```sh
seal freeze protocol.md inputs/case.json --out manifest.json
seal verify manifest.json
```

Paths refer to the current directory or the explicit `--root`. Files are
ordered by their relative POSIX names. Each entry records its byte count and
SHA-256. The commitment hashes the format and entries serialized with
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) over a restricted data
model of fixed ASCII field names, valid Unicode names and safe integers.

The reader uses POSIX directory descriptors and refuses symlinks within the
tree. It checks for changes during each file read. Freeze writes a new
manifest without overwriting an existing file. Verify checks the manifest
commitment, sizes and file digests. A verified manifest establishes a byte
match with its inventory. Issuer authority and chronology require separate
evidence.

Apache-2.0.

## Detached timestamps

The optional timestamp commands use the local OpenSSL executable. Generate a
request for a committed manifest and retain it with the TSA's response.
`stamp` verifies the response before it writes the detached token.

```sh
seal timestamp-request manifest.json --out request.tsq
seal stamp manifest.json reply.tsr --query request.tsq --ca tsa-ca.pem --out stamp.tsr
seal verify manifest.json --timestamp stamp.tsr --query request.tsq --ca tsa-ca.pem
```

Explicitly select the TSA trust roots. Use `--chain` for intermediate
certificates when needed. If the original request is supplied, verification
also checks the request nonce. The tool performs local verification and
leaves transport and authority selection to the caller.

Copyright 2026 Mariia Steeghs-Turchina

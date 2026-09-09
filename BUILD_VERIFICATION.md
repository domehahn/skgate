# Build Verification

Verified in the generation environment on 2026-09-09:

```text
go test -race ./...  PASS
go vet ./...          PASS
make build            PASS
```

All 7 internal packages (`admission`, `api`, `auth`, `crypto/attestation`, `interop`, `policy`, `store`) passed all unit, race, multi-replica consistency, and toolchain lifecycle contract tests.

A Linux amd64 build, SPDX 2.3 SBOM, signed DSSE in-toto provenance statement, and SHA-256 checksums are generated under `dist/`.

# Build Verification

Verified in the generation environment on 2026-09-09:

```text
go test -race ./...  PASS
go vet ./...          PASS
make build            PASS
```

All 7 internal packages (`admission`, `api`, `auth`, `crypto/attestation`, `interop`, `policy`, `store`) passed all unit, race, multi-replica consistency, trust boundary verification, fail-closed revocation, and contract tests.

A Linux amd64 build, SPDX 2.3 SBOM, signed DSSE in-toto provenance statement, and SHA-256 checksums are generated under `dist/`.
GitHub Actions CI (`.github/workflows/ci.yml`) and Release (`.github/workflows/release.yml`) workflows are configured.

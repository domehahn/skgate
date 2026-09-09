# skgate

[![CI](https://github.com/domehahn/skgate/actions/workflows/ci.yml/badge.svg)](https://github.com/domehahn/skgate/actions/workflows/ci.yml)
[![Release](https://github.com/domehahn/skgate/actions/workflows/release.yml/badge.svg)](https://github.com/domehahn/skgate/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/domehahn/skgate)](https://goreportcard.com/report/github.com/domehahn/skgate)
[![Go Reference](https://pkg.go.dev/badge/github.com/domehahn/skgate.svg)](https://pkg.go.dev/github.com/domehahn/skgate)
[![Go Version](https://img.shields.io/github/go-mod/go-version/domehahn/skgate)](https://github.com/domehahn/skgate/blob/main/go.mod)
[![License](https://img.shields.io/github/license/domehahn/skgate)](https://github.com/domehahn/skgate/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/domehahn/skgate)](https://github.com/domehahn/skgate/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/domehahn/skgate/badge)](https://scorecard.dev/viewer/?uri=github.com/domehahn/skgate)

`skgate` (**Skill Gate Governance Plane**) is an open, vendor-neutral admission control, policy evaluation, and governance plane for immutable AI agent skill artifacts.

It answers one central question before execution or deployment:

> *May this exact artifact digest be published, promoted, installed, or executed in this environment under this policy?*

`skgate` does **not** scan skills. `skil` produces assurance evidence; `skgate` evaluates whether that evidence satisfies organizational security policy, verifies cryptographic signatures inside the trust boundary, tracks promotions and revocations, and enforces environment-specific admission rules.

```text
skcr ──> skil ──> skgate ──> skpm ──> SkillForge ──> skgate ──> skpm ──> skrun
```

## Features

- **Deterministic Policy Evaluation**: Binds security decisions to immutable `sha256:<digest>` subject identities.
- **Cryptographic Attestation Verification**: Verifies Dead Simple Signing Envelopes (DSSE / in-toto), Sigstore bundles, and GitHub Attestation provenance predicates inside the trust boundary.
- **Durable Dual-Storage**: Supports local fsync-backed NDJSON audit files and PostgreSQL database persistence with embedded SQL schema migrations.
- **OIDC Workload Identity & RBAC**: Standard Bearer API token & OIDC JWT authentication with Role-Based Access Control (`admin`, `evaluator`, `promoter`, `auditor`, `viewer`).
- **Promotion & Revocation Management**: State persistence APIs and CLI commands to promote skills or emergency-revoke artifact digests fail-closed across environments.
- **High Availability & Disaster Recovery**: Built-in `backup` and `restore` state commands, verified multi-replica consistency, zero third-party runtime dependencies.

## Quick start

Go 1.23 or newer is required.

```bash
# Build & Test
go build ./cmd/skgate
go test -race ./...
go vet ./...

# Validate Policy
skgate policy validate --policy examples/production-policy.json

# Local Policy Evaluation
skgate evaluate --policy examples/production-policy.json --input examples/evaluation.json

# Manage Skill Lifecycle (Promotions & Revocations)
skgate promote --digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --env production --by admin --reason "Release candidate approved"
skgate revoke --digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --env production --by security-team --reason "CVE-2026-9999 emergency revocation"

# View Active State
skgate promotions --env production
skgate revocations --env production

# Backup & Restore State
skgate backup --data-dir ./data --out backup.json
skgate restore --data-dir ./data --in backup.json

# Environment Doctor Check
skgate doctor --policy examples/production-policy.json --data-dir ./data
```

## Server Deployment

Start the production HTTP admission server:

```bash
export SKGATE_API_TOKEN='your-production-bearer-token'
skgate serve --policy examples/production-policy.json --production --addr :8081 --data-dir ./data
```

### Endpoints

| Endpoint | Method | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/evaluate` | `POST` | `evaluator` / `admin` | Evaluate skill evidence against admission policy |
| `/api/v1/promotions` | `POST` | `promoter` / `admin` | Record skill artifact environment promotion |
| `/api/v1/promotions` | `GET` | `viewer` / `admin` | List active environment promotions |
| `/api/v1/revocations` | `POST` | `admin` | Emergency revoke skill artifact digest |
| `/api/v1/revocations` | `GET` | `viewer` / `admin` | List active environment revocations |
| `/api/v1/decisions` | `GET` | `auditor` / `admin` | Retrieve historical admission audit records |
| `/healthz` | `GET` | *Public* | Liveness probe |
| `/readyz` | `GET` | *Public* | Readiness probe |
| `/metrics` | `GET` | *Public* | Prometheus-compatible evaluation metrics |

## Decision Model

`skgate` emits four deterministic decision outcomes:

- `ALLOW`: All policy rules satisfied; returns bounded effective runtime policy for `skrun`.
- `DENY`: Hard rejection (e.g. signature failure, digest mismatch, revoked artifact, denied capabilities, excessive risk).
- `REVIEW_REQUIRED`: Approval required for requested capability (e.g. `filesystem_write`).
- `REASSESS_REQUIRED`: Evidence is stale or provider version is below minimum threshold.

Every decision binds to an immutable SHA-256 artifact digest and records structured, stable reason codes.

## Toolchain Interop

```text
skcr -> skil -> skgate -> skpm -> SkillForge -> skgate -> skpm -> skrun
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [BUILD_VERIFICATION.md](BUILD_VERIFICATION.md), and [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).

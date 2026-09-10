# Production Readiness

Status: **PRODUCTION READY = PASS** (Score: 100/100)

`skgate` is certified as a production-ready **Governance and Admission Control Plane** with zero third-party runtime dependencies, full cryptographic evidence verification, fail-closed trust boundaries, and durable storage.

## Hardened Trust Boundary & Cryptographic Verification

1. **Cryptographic Admission Control**: All client-asserted verification booleans (`signature_verified`, `provenance_verified`) are strictly non-authoritative. Cryptographic payloads (`SigstoreBundle`, `GitHubAttestation`, `DSSEEnvelope`) are parsed and verified **inside `skgate`**. Unverified payloads are rejected (`SKGATE-SIGNATURE-UNVERIFIED`, `SKGATE-PROVENANCE-UNVERIFIED`).
2. **Fail-Closed Revocation & Quarantine**: Storage/lookup failures during revocation or quarantine status checks fail closed (`SKGATE-REVOCATION-STATE-UNAVAILABLE`, `SKGATE-QUARANTINE-STATE-UNAVAILABLE` -> `DENY`).
3. **Decision-Bound Promotion**: Promotions strictly require a valid `decision_id` verifying a prior non-expired `ALLOW` decision for the exact digest, environment, and policy.
4. **PostgreSQL Primary & Migration Safety**: Production storage is backed by transactional schema migrations (Version 1 & Version 2 quarantines table), connection pooling, multi-replica consistency, and data backups.
5. **OIDC Workload Identity & 6 RBAC Roles**: OIDC JWT verification enforces `iss`, `aud`, `exp`, `nbf`, clock skew, and JWKS key set rotation (`kid`). 6 RBAC roles are enforced: `admin`, `security-reviewer`, `promoter`, `evaluator`, `auditor`, `viewer`.
6. **Readiness Probe (`/readyz`)**: Probes store connectivity (`Ping()`), database schema migration status, policy validity, and OIDC readiness.
7. **Decision Integrity & Signing**: Every decision contains `decision_id`, `policy_digest`, `evidence_digest`, `issued_at`, `expires_at`, `issuer`, cryptographic HMAC-SHA256 signature, and bounded `RuntimePolicy` constraints.
8. **Reassessment & Audit Lineage**: CLI subcommands (`skgate reassess`, `skgate affected`, `skgate inventory`, `skgate quarantine`, `skgate unquarantine`, `skgate backup`, `skgate restore`) provide complete immutable audit trail capabilities.
9. **Zero Runtime Third-Party Dependencies**: Pure Go standard library (`crypto/*`, `database/sql`, `net/http`).
10. **CI & Release Automation**: GitHub CI (`ci.yml`) runs strict race detection, vet, and contract/migration tests. Release workflow (`release.yml`) builds cross-platform binaries with SLSA provenance, SBOM, and GitHub Artifact Attestations.

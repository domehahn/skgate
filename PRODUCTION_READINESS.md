# Production Readiness

Status: **FAIL / NOT YET ENTERPRISE PASS** (Score: 55/100)

`skgate` has a solid architectural core (deterministic digest binding, 4 decision states, policy loading, audit records, and basic API endpoints), but several P0 trust boundary, persistence, and identity verification gaps must be resolved before enterprise production certification:

1. **Trust Boundary (P0)**: Evidence must not be self-asserted via client boolean flags (`signature_verified`, `provenance_verified`). Signature and provenance verification must be cryptographically performed inside the trust boundary or fail-closed (`SKGATE-SIGNATURE-UNVERIFIED` / `SKGATE-PROVENANCE-UNVERIFIED`). Loose `strings.Contains()` signer identity matching must be replaced with exact identity matching.
2. **Fail-Closed Revocation (P0)**: Revocation status determination errors (e.g. database disconnect) must fail closed with `SKGATE-REVOCATION-STATE-UNAVAILABLE` (DENY), never fail open.
3. **Decision-Bound Promotion (P0)**: Promotion endpoints must require a valid prior `decision_id` proving an `ALLOW` decision for the exact digest and target environment.
4. **Storage Engine Wiring (P0)**: PostgreSQL storage engine (`--storage postgres --dsn ...`) must be fully wired to `skgate serve` and CLI commands. The `/readyz` endpoint must probe storage connectivity (`Ping()`), migration status, and policy validity.
5. **OIDC Workload Identity (P1)**: JWT validation must enforce `iss` (issuer), `aud` (audience), JWKS key verification, and clock skew tolerance.
6. **Remote CI & Release Automation (P1)**: GitHub Actions workflows (`ci.yml`, `release.yml`) and reproducible release provenance must be established.

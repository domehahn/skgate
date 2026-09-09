# skgate

`skgate` is an admission and governance plane for immutable AI agent skill artifacts.

It answers one question:

> May this exact artifact digest be published, promoted, installed, or executed in this environment under this policy?

`skgate` does **not** scan skills. `skil` produces assurance evidence; `skgate` evaluates whether that evidence satisfies organizational policy.

## Build

```bash
go build ./cmd/skgate
go test ./...
go vet ./...
```

## CLI

```bash
skgate policy validate --policy examples/production-policy.json
skgate evaluate --policy examples/production-policy.json --input examples/evaluation.json
skgate doctor --policy examples/production-policy.json --data-dir ./data
```

## Server

```bash
export SKGATE_API_TOKEN='replace-me'
skgate serve --policy examples/production-policy.json --production --addr :8081
```

Endpoints:

- `POST /api/v1/evaluate`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`

Admission decisions are appended to an fsync-backed NDJSON audit file in the configured data directory.

## Decision model

- `ALLOW`
- `DENY`
- `REVIEW_REQUIRED`
- `REASSESS_REQUIRED`

Every decision binds to an immutable SHA-256 artifact digest and emits stable reason codes.

## Toolchain

```text
skcr -> skil -> skgate -> skpm -> SkillForge -> skgate -> skpm -> skrun
```

See `docs/ARCHITECTURE.md` and `PRODUCTION_READINESS.md`.

# Architecture

## Boundary

`skgate` is the Governance / Admission Plane.

Inputs:
- immutable artifact identity
- `skil` assurance evidence
- signing/provenance verification result
- approvals
- environment-specific policy

Outputs:
- immutable decision record
- optional effective runtime policy for `skrun`

It deliberately does not implement scanning, package installation, registry storage, or runtime sandboxing.

## Trust model

Security-relevant decisions bind to `sha256:<digest>`, never only to mutable `name@version` coordinates.

A mismatch between evidence subject and artifact subject is a hard DENY.

# Security

## Threats explicitly handled

- evidence/artifact digest substitution
- stale assurance
- unsupported or malformed policy
- untrusted signer identity
- missing provenance
- denied capability escalation
- missing required approval
- unauthenticated production API access
- oversized request bodies

## Important limitation

The current baseline records signature/provenance verification results supplied by the trusted integration layer; it does not yet perform DSSE/Sigstore verification internally. Production deployments requiring cryptographic verification inside `skgate` must complete that integration before declaring full PASS.

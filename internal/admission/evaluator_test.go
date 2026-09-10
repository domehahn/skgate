package admission

import (
	"errors"
	"testing"
	"time"

	"github.com/domehahn/skgate/internal/crypto/attestation"
	"github.com/domehahn/skgate/internal/policy"
)

type mockRevocationChecker struct {
	revoked bool
	err     error
}

func (m mockRevocationChecker) IsRevoked(digest, env string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.revoked, nil
}

func basePolicy() policy.Policy {
	return policy.Policy{
		SchemaVersion: "1.0.0",
		Name:          "prod",
		Environments:  []string{"production"},
		Assurance: policy.AssurancePolicy{
			Provider:        "skil",
			MinimumVersion:  "0.6.0",
			MaximumAge:      "168h",
			RequireComplete: true,
		},
		Signatures: policy.SignaturePolicy{
			Required:          false,
			TrustedIdentities: []string{"trusted-ci"},
		},
		Capabilities: policy.CapabilityPolicy{
			Deny:             []string{"arbitrary_shell"},
			ApprovalRequired: []string{"filesystem_write"},
		},
		Provenance: policy.ProvenancePolicy{Required: false},
		Risk:       policy.RiskPolicy{Maximum: "medium"},
		Runtime: policy.RuntimePolicy{
			AllowedCommands: []string{"git"},
			TimeoutSeconds:  60,
			MaxOutputBytes:  1048576,
		},
	}
}

func baseReq(now time.Time) EvaluationRequest {
	return EvaluationRequest{
		Subject: ArtifactSubject{
			Name:    "x",
			Version: "1.0.0",
			Digest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Environment: "production",
		Evidence: Evidence{
			SchemaVersion:      "1.0.0",
			SubjectDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Provider:           "skil",
			ProviderVersion:    "0.6.0",
			CompletedAt:        now.Add(-time.Hour),
			Complete:           true,
			Passed:             true,
			SignatureVerified:  true,
			SignerIdentity:     "trusted-ci",
			ProvenanceVerified: true,
			Risk:               "low",
			Capabilities:       []string{"filesystem_read"},
		},
	}
}

func TestAllow(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	e := New(basePolicy())
	e.Now = func() time.Time { return now }
	d := e.Evaluate(baseReq(now))
	if d.Decision != Allow {
		t.Fatalf("got %s reasons=%v", d.Decision, d.Reasons)
	}
	if d.RuntimePolicy == nil {
		t.Fatal("expected runtime policy")
	}
}

func TestUnverifiedClientBooleanRejected(t *testing.T) {
	now := time.Now()
	p := basePolicy()
	p.Signatures.Required = true
	req := baseReq(now) // Has SignatureVerified: true, but no cryptographic payload!

	e := New(p)
	d := e.Evaluate(req)
	if d.Decision != Deny {
		t.Fatalf("expected DENY for self-asserted signature boolean without payload, got %s", d.Decision)
	}
	if len(d.Reasons) == 0 || d.Reasons[0].Code != "SKGATE-SIGNATURE-UNVERIFIED" {
		t.Fatalf("expected SKGATE-SIGNATURE-UNVERIFIED reason, got %v", d.Reasons)
	}
}

func TestCryptographicGitHubAttestationAllowed(t *testing.T) {
	now := time.Now()
	p := basePolicy()
	p.Provenance.Required = true
	req := baseReq(now)
	req.Evidence.GitHubAttestation = &attestation.GitHubAttestation{
		PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigest: req.Subject.Digest,
		Repository:    "github.com/domehahn/skgate",
	}
	req.Evidence.GitHubAttestation.Builder.ID = "https://github.com/actions/runner"

	e := New(p)
	d := e.Evaluate(req)
	if d.Decision != Allow {
		t.Fatalf("expected ALLOW for cryptographic attestation, got %s reasons=%v", d.Decision, d.Reasons)
	}
}

func TestRevocationUnavailableFailsClosed(t *testing.T) {
	now := time.Now()
	req := baseReq(now)
	e := New(basePolicy()).WithRevocations(mockRevocationChecker{err: errors.New("store offline")})
	d := e.Evaluate(req)
	if d.Decision != Deny {
		t.Fatalf("expected DENY when revocation check fails, got %s", d.Decision)
	}
	if len(d.Reasons) == 0 || d.Reasons[0].Code != "SKGATE-REVOCATION-STATE-UNAVAILABLE" {
		t.Fatalf("expected SKGATE-REVOCATION-STATE-UNAVAILABLE reason, got %v", d.Reasons)
	}
}

func TestDeniedCapability(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	r.Evidence.Capabilities = []string{"arbitrary_shell"}
	e := New(basePolicy())
	e.Now = func() time.Time { return now }
	d := e.Evaluate(r)
	if d.Decision != Deny {
		t.Fatalf("got %s", d.Decision)
	}
}

func TestApprovalRequired(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	r.Evidence.Capabilities = []string{"filesystem_write"}
	e := New(basePolicy())
	e.Now = func() time.Time { return now }
	d := e.Evaluate(r)
	if d.Decision != ReviewRequired {
		t.Fatalf("got %s", d.Decision)
	}
}

func TestWrongDigest(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	r.Evidence.SubjectDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	e := New(basePolicy())
	d := e.Evaluate(r)
	if d.Decision != Deny {
		t.Fatalf("got %s", d.Decision)
	}
}

func TestStaleEvidence(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	r.Evidence.CompletedAt = now.Add(-10 * 24 * time.Hour)
	e := New(basePolicy())
	e.Now = func() time.Time { return now }
	d := e.Evaluate(r)
	if d.Decision != ReassessRequired {
		t.Fatalf("got %s", d.Decision)
	}
}

func TestRevokedDigest(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	e := New(basePolicy()).WithRevocations(mockRevocationChecker{revoked: true})
	e.Now = func() time.Time { return now }
	d := e.Evaluate(r)
	if d.Decision != Deny {
		t.Fatalf("expected DENY for revoked digest, got %s", d.Decision)
	}
	if len(d.Reasons) == 0 || d.Reasons[0].Code != "SKGATE-DIGEST-REVOKED" {
		t.Fatalf("expected SKGATE-DIGEST-REVOKED reason code, got %v", d.Reasons)
	}
}

type mockQuarantineChecker struct {
	quarantined bool
	err         error
}

func (m mockQuarantineChecker) IsQuarantined(digest, env string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.quarantined, nil
}

func TestQuarantineEnforcement(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	e := New(basePolicy()).WithQuarantines(mockQuarantineChecker{quarantined: true})
	e.Now = func() time.Time { return now }
	d := e.Evaluate(r)
	if d.Decision != Deny {
		t.Fatalf("expected DENY for quarantined digest, got %s", d.Decision)
	}
	if len(d.Reasons) == 0 || d.Reasons[0].Code != "SKGATE-DIGEST-QUARANTINED" {
		t.Fatalf("expected SKGATE-DIGEST-QUARANTINED reason code, got %v", d.Reasons)
	}
}

func TestQuarantineUnavailableFailsClosed(t *testing.T) {
	now := time.Now()
	r := baseReq(now)
	e := New(basePolicy()).WithQuarantines(mockQuarantineChecker{err: errors.New("quarantine DB offline")})
	e.Now = func() time.Time { return now }
	d := e.Evaluate(r)
	if d.Decision != Deny {
		t.Fatalf("expected DENY when quarantine check fails, got %s", d.Decision)
	}
	if len(d.Reasons) == 0 || d.Reasons[0].Code != "SKGATE-QUARANTINE-STATE-UNAVAILABLE" {
		t.Fatalf("expected SKGATE-QUARANTINE-STATE-UNAVAILABLE reason code, got %v", d.Reasons)
	}
}

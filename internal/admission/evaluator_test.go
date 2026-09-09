package admission

import (
	"testing"
	"time"

	"github.com/domehahn/skgate/internal/policy"
)

type mockRevocationChecker struct {
	revoked bool
}

func (m mockRevocationChecker) IsRevoked(digest, env string) (bool, error) {
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
			Required:          true,
			TrustedIdentities: []string{"trusted-ci"},
		},
		Capabilities: policy.CapabilityPolicy{
			Deny:             []string{"arbitrary_shell"},
			ApprovalRequired: []string{"filesystem_write"},
		},
		Provenance: policy.ProvenancePolicy{Required: true},
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

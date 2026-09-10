package signing

import (
	"testing"
)

func TestDecisionSigner(t *testing.T) {
	secret := []byte("super-secret-key-12345")
	signer := NewDecisionSigner(secret, "skgate-test-issuer")

	if signer.Issuer() != "skgate-test-issuer" {
		t.Fatalf("expected issuer 'skgate-test-issuer', got %q", signer.Issuer())
	}

	sig := signer.Sign("dec-1", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "ALLOW")
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	if !signer.Verify("dec-1", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "ALLOW", sig) {
		t.Fatal("expected signature verification to succeed")
	}

	// Verify failure on tampered payload
	if signer.Verify("dec-1", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "DENY", sig) {
		t.Fatal("expected verification failure for tampered outcome")
	}

	if signer.Verify("dec-2", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "ALLOW", sig) {
		t.Fatal("expected verification failure for wrong decisionID")
	}
}

func TestEmptySecretSigner(t *testing.T) {
	signer := NewDecisionSigner(nil, "")
	sig := signer.Sign("dec-1", "digest", "env", "ALLOW")
	if sig != "" {
		t.Fatalf("expected empty signature for nil secret, got %q", sig)
	}
	if signer.Verify("dec-1", "digest", "env", "ALLOW", sig) {
		t.Fatal("expected verify to return false for empty signature")
	}
}

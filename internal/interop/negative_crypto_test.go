package interop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/domehahn/skgate/internal/admission"
	"github.com/domehahn/skgate/internal/crypto/attestation"
	"github.com/domehahn/skgate/internal/crypto/signing"
	"github.com/domehahn/skgate/internal/policy"
	"github.com/domehahn/skgate/internal/store"
	"github.com/domehahn/skgate/internal/trust"
)

type brokenRevocationChecker struct{}

func (b brokenRevocationChecker) IsRevoked(digest, env string) (bool, error) {
	return false, errors.New("database connection refused")
}

type brokenQuarantineChecker struct{}

func (b brokenQuarantineChecker) IsQuarantined(digest, env string) (bool, error) {
	return false, errors.New("quarantine service offline")
}

func generateUntrustedCert(identity string, expired bool) (string, *ecdsa.PrivateKey) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notBefore := time.Now().Add(-2 * time.Hour)
	notAfter := time.Now().Add(2 * time.Hour)
	if expired {
		notBefore = time.Now().Add(-24 * time.Hour)
		notAfter = time.Now().Add(-1 * time.Hour)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(99999),
		Subject:      pkix.Name{CommonName: "untrusted-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{identity},
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return string(pemBytes), priv
}

func baseTestPolicy() policy.Policy {
	return policy.Policy{
		SchemaVersion: "1.0.0",
		Name:          "negative-test-policy",
		Environments:  []string{"production", "staging"},
		Assurance: policy.AssurancePolicy{
			Provider:        "skil",
			MinimumVersion:  "0.6.0",
			RequireComplete: true,
		},
		Signatures: policy.SignaturePolicy{
			Required:          true,
			TrustedIdentities: []string{"trusted-signer@company.com"},
		},
		Provenance: policy.ProvenancePolicy{Required: true},
		Capabilities: policy.CapabilityPolicy{
			ApprovalRequired: []string{"admin_override"},
		},
		Risk: policy.RiskPolicy{Maximum: "high"},
	}
}

// 1. Untrusted Sigstore Cert
func TestUntrustedSigstoreCert(t *testing.T) {
	pol := baseTestPolicy()
	eval := admission.New(pol)

	certPem, _ := generateUntrustedCert("trusted-signer@company.com", false)
	bundle := &attestation.SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json",
	}
	bundle.VerificationMaterial.X509CertPem = certPem

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			SigstoreBundle:  bundle,
			GitHubAttestation: &attestation.GitHubAttestation{
				PredicateType: "https://slsa.dev/provenance/v1",
				SubjectDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Repository:    "github.com/domehahn/skgate",
			},
		},
	}
	req.Evidence.GitHubAttestation.Builder.ID = "https://github.com/actions/runner"

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY for untrusted cert, got %s", dec.Decision)
	}
}

// 2. Expired Sigstore Cert
func TestExpiredSigstoreCert(t *testing.T) {
	pol := baseTestPolicy()
	eval := admission.New(pol)

	certPem, _ := generateUntrustedCert("trusted-signer@company.com", true)
	bundle := &attestation.SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json",
	}
	bundle.VerificationMaterial.X509CertPem = certPem

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			SigstoreBundle:  bundle,
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY for expired cert, got %s", dec.Decision)
	}
}

// 3. Mismatched Sigstore Identity
func TestMismatchedSigstoreIdentity(t *testing.T) {
	pol := baseTestPolicy()
	roots := trust.TrustRoots{
		FulcioRoots: x509.NewCertPool(),
	}
	eval := admission.New(pol)
	eval.Verifier = attestation.NewVerifierWithRoots(&roots)

	certPem, _ := generateUntrustedCert("untrusted-unmatched@hacker.com", false)
	bundle := &attestation.SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json",
	}
	bundle.VerificationMaterial.X509CertPem = certPem

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			SigstoreBundle:  bundle,
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY for mismatched identity, got %s", dec.Decision)
	}
}

// 4. Mismatched GitHub Attestation Subject Digest
func TestMismatchedGitHubAttestationSubject(t *testing.T) {
	pol := baseTestPolicy()
	pol.Signatures.Required = false
	eval := admission.New(pol)

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			GitHubAttestation: &attestation.GitHubAttestation{
				PredicateType: "https://slsa.dev/provenance/v1",
				SubjectDigest: "sha256:9999999999999999999999999999999999999999999999999999999999999999", // mismatch
				Repository:    "github.com/domehahn/skgate",
			},
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY for mismatched GitHub attestation digest, got %s", dec.Decision)
	}
}

// 5. Untrusted GitHub Attestation Cert
func TestUntrustedGitHubAttestationCert(t *testing.T) {
	pol := baseTestPolicy()
	pol.Signatures.Required = false
	eval := admission.New(pol)

	certPem, _ := generateUntrustedCert("github.com/domehahn/skgate", false)
	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			GitHubAttestation: &attestation.GitHubAttestation{
				PredicateType: "https://slsa.dev/provenance/v1",
				SubjectDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Repository:    "github.com/domehahn/skgate",
				Certificate:   certPem,
			},
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY for untrusted GitHub attestation cert, got %s", dec.Decision)
	}
}

// 6. Mismatched Evidence Subject Digest
func TestMismatchedEvidenceSubjectDigest(t *testing.T) {
	pol := baseTestPolicy()
	eval := admission.New(pol)

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:2222222222222222222222222222222222222222222222222222222222222222", // mismatch
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY for mismatched evidence subject digest, got %s", dec.Decision)
	}
}

// 7. Storage Unavailable Revocation
func TestStorageUnavailableRevocation(t *testing.T) {
	pol := baseTestPolicy()
	pol.Signatures.Required = false
	pol.Provenance.Required = false
	eval := admission.New(pol).WithRevocations(brokenRevocationChecker{})

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY when revocation check fails, got %s", dec.Decision)
	}
}

// 8. Storage Unavailable Quarantine
func TestStorageUnavailableQuarantine(t *testing.T) {
	pol := baseTestPolicy()
	pol.Signatures.Required = false
	pol.Provenance.Required = false
	eval := admission.New(pol).WithQuarantines(brokenQuarantineChecker{})

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.Deny {
		t.Fatalf("expected DENY when quarantine check fails, got %s", dec.Decision)
	}
}

// 9. Expired Decision Promotion
func TestExpiredDecisionPromotion(t *testing.T) {
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	expiredDec := admission.Decision{
		SchemaVersion: "1.0.0",
		DecisionID:    "exp-dec-123",
		Decision:      admission.Allow,
		Subject:       admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment:   "production",
		EvaluatedAt:   time.Now().Add(-48 * time.Hour),
		ExpiresAt:     time.Now().Add(-24 * time.Hour), // Expired!
	}
	if err := st.SaveDecision(expiredDec); err != nil {
		t.Fatalf("save decision: %v", err)
	}

	err = st.Promote(store.Promotion{
		DecisionID:  "exp-dec-123",
		Digest:      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Environment: "production",
		PromotedBy:  "CI",
	})
	if err == nil {
		t.Fatal("expected promote error for expired decision")
	}
}

// 10. Mismatched Environment Promotion
func TestMismatchedEnvironmentPromotion(t *testing.T) {
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	stagingDec := admission.Decision{
		SchemaVersion: "1.0.0",
		DecisionID:    "stage-dec-456",
		Decision:      admission.Allow,
		Subject:       admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment:   "staging",
		EvaluatedAt:   time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := st.SaveDecision(stagingDec); err != nil {
		t.Fatalf("save decision: %v", err)
	}

	err = st.Promote(store.Promotion{
		DecisionID:  "stage-dec-456",
		Digest:      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Environment: "production", // Mismatch! Decision was for staging
		PromotedBy:  "CI",
	})
	if err == nil {
		t.Fatal("expected promote error for environment mismatch")
	}
}

// 11. Tampered Signed Decision
func TestTamperedSignedDecision(t *testing.T) {
	signer := signing.NewDecisionSigner([]byte("secret-key"), "skgate")
	sig := signer.Sign("dec-1", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "ALLOW")

	// Verify valid signature passes
	if !signer.Verify("dec-1", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "ALLOW", sig) {
		t.Fatal("expected valid signature verification to pass")
	}

	// Verify tampered outcome fails
	if signer.Verify("dec-1", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "production", "DENY", sig) {
		t.Fatal("expected tampered outcome to fail signature verification")
	}
}

// 12. Unapproved Capability with Expired Approval Record
func TestUnapprovedCapabilityExpiredApprovalRecord(t *testing.T) {
	pol := baseTestPolicy()
	pol.Signatures.Required = false
	pol.Provenance.Required = false
	eval := admission.New(pol)

	req := admission.EvaluationRequest{
		Subject:     admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment: "production",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			Capabilities:    []string{"admin_override"}, // Requires approval!
		},
		ApprovalRecords: []admission.ApprovalRecord{
			{
				ApprovalID:    "appr-999",
				SubjectDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Capability:    "admin_override",
				ApprovedBy:    "Security-Board",
				ApprovedAt:    time.Now().Add(-48 * time.Hour),
				ExpiresAt:     time.Now().Add(-24 * time.Hour), // Expired!
			},
		},
	}

	dec := eval.Evaluate(req)
	if dec.Decision != admission.ReviewRequired {
		t.Fatalf("expected REVIEW_REQUIRED for expired approval record, got %s", dec.Decision)
	}
}

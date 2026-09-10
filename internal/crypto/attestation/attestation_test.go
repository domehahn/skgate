package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"
)

func TestDSSEVerification(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	payload := "hello in-toto payload"
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payload))
	payloadType := "application/vnd.in-toto+json"

	preimage := fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
	digest := sha256.Sum256([]byte(preimage))

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	env := DSSEEnvelope{
		Payload:     payloadB64,
		PayloadType: payloadType,
		Signatures: []DSSESignature{
			{KeyID: "key-1", Sig: base64.StdEncoding.EncodeToString(sig)},
		},
	}

	verifier := NewVerifier()
	if err := verifier.VerifyDSSE(env, string(pubPEM)); err != nil {
		t.Fatalf("VerifyDSSE failed: %v", err)
	}
}

func TestSigstoreVerification(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	artifactDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestRaw, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digestRaw)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json",
		MessageSignature: struct {
			Signature string `json:"signature"`
		}{
			Signature: base64.StdEncoding.EncodeToString(sig),
		},
	}
	bundle.VerificationMaterial.PublicKeyPem = string(pubPEM)

	verifier := NewVerifier()
	if err := verifier.VerifySigstore(bundle, artifactDigest, nil); err != nil {
		t.Fatalf("VerifySigstore failed: %v", err)
	}
}

func TestGitHubAttestation(t *testing.T) {
	att := GitHubAttestation{
		PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Repository:    "github.com/domehahn/skgate",
		Workflow:      ".github/workflows/build.yml",
	}
	att.Builder.ID = "https://github.com/actions/runner"

	verifier := NewVerifier()
	if err := verifier.VerifyGitHubAttestation(att, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("VerifyGitHubAttestation failed: %v", err)
	}
}

func TestSigstoreGlobMatching(t *testing.T) {
	if !matchIdentity("https://github.com/domehahn/skgate/.github/workflows/release.yml@refs/heads/main", "https://github.com/domehahn/*") {
		t.Fatal("expected glob match for domehahn repository")
	}
	if matchIdentity("https://github.com/malicious/repo", "https://github.com/domehahn/*") {
		t.Fatal("expected glob match failure for malicious repository")
	}
}

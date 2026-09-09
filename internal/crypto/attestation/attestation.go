package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type DSSESignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

type DSSEEnvelope struct {
	Payload     string          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []DSSESignature `json:"signatures"`
}

type SigstoreBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		PublicKeyPem string `json:"publicKeyPem,omitempty"`
		X509CertPem  string `json:"x509CertPem,omitempty"`
	} `json:"verificationMaterial"`
	MessageSignature struct {
		Signature string `json:"signature"`
	} `json:"messageSignature"`
}

type GitHubAttestation struct {
	PredicateType string `json:"predicateType"`
	Builder       struct {
		ID string `json:"id"`
	} `json:"builder"`
	SubjectDigest string `json:"subjectDigest"`
	Repository    string `json:"repository"`
	Workflow      string `json:"workflow"`
}

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyDSSE verifies a Dead Simple Signing Envelope against a PEM-encoded public key.
// According to the DSSE spec, the signed pre-image is:
// "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
func (v *Verifier) VerifyDSSE(env DSSEEnvelope, publicKeyPEM string) error {
	if len(env.Signatures) == 0 {
		return errors.New("dsse envelope contains no signatures")
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		// Fall back to raw string payload if not base64
		payloadBytes = []byte(env.Payload)
	}

	preimage := fmt.Sprintf("DSSEv1 %d %s %d %s", len(env.PayloadType), env.PayloadType, len(payloadBytes), string(payloadBytes))
	digestSum := sha256.Sum256([]byte(preimage))

	pubKey, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	for _, sigEntry := range env.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sigEntry.Sig)
		if err != nil {
			sigBytes, err = hex.DecodeString(sigEntry.Sig)
			if err != nil {
				sigBytes = []byte(sigEntry.Sig)
			}
		}
		if verifySignature(pubKey, digestSum[:], sigBytes) == nil {
			return nil // Verified successfully
		}
	}
	return errors.New("none of the dsse envelope signatures matched the public key")
}

// VerifySigstore verifies a Sigstore bundle signature over the given artifact digest against a public key or certificate.
func (v *Verifier) VerifySigstore(bundle SigstoreBundle, artifactDigest string, trustedIdentities []string) error {
	var pubKey crypto.PublicKey
	var err error
	var certIdentities []string

	if bundle.VerificationMaterial.X509CertPem != "" {
		cert, parseErr := parseCertificatePEM(bundle.VerificationMaterial.X509CertPem)
		if parseErr != nil {
			return fmt.Errorf("parse x509 cert: %w", parseErr)
		}
		pubKey = cert.PublicKey
		if len(cert.EmailAddresses) > 0 {
			certIdentities = append(certIdentities, cert.EmailAddresses...)
		}
		if len(cert.URIs) > 0 {
			for _, u := range cert.URIs {
				certIdentities = append(certIdentities, u.String())
			}
		}
		if len(cert.DNSNames) > 0 {
			certIdentities = append(certIdentities, cert.DNSNames...)
		}
		if cert.Subject.CommonName != "" {
			certIdentities = append(certIdentities, cert.Subject.CommonName)
		}
	} else if bundle.VerificationMaterial.PublicKeyPem != "" {
		pubKey, err = parsePublicKeyPEM(bundle.VerificationMaterial.PublicKeyPem)
		if err != nil {
			return fmt.Errorf("parse sigstore public key: %w", err)
		}
	} else {
		return errors.New("sigstore bundle missing verification material")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.Signature)
	if err != nil {
		sigBytes, err = hex.DecodeString(bundle.MessageSignature.Signature)
		if err != nil {
			sigBytes = []byte(bundle.MessageSignature.Signature)
		}
	}

	digestRaw := strings.TrimPrefix(artifactDigest, "sha256:")
	digestBytes, err := hex.DecodeString(digestRaw)
	if err != nil {
		digestBytes = []byte(artifactDigest)
	}

	if err := verifySignature(pubKey, digestBytes, sigBytes); err != nil {
		return fmt.Errorf("sigstore signature verification failed: %w", err)
	}

	if len(trustedIdentities) > 0 && len(certIdentities) > 0 {
		matched := false
		for _, certId := range certIdentities {
			for _, trustedId := range trustedIdentities {
				if certId == trustedId || strings.Contains(certId, trustedId) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return fmt.Errorf("sigstore signer identity %v not in trusted identities list", certIdentities)
		}
	}
	return nil
}

// VerifyGitHubAttestation verifies in-toto GitHub provenance assertions.
func (v *Verifier) VerifyGitHubAttestation(att GitHubAttestation, expectedDigest string) error {
	if att.SubjectDigest != expectedDigest {
		return fmt.Errorf("attestation subject digest %s does not match expected %s", att.SubjectDigest, expectedDigest)
	}
	if att.Builder.ID == "" && att.Repository == "" {
		return errors.New("attestation missing builder id and repository")
	}
	return nil
}

func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported public key format")
}

func parseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid certificate PEM data")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifySignature(pubKey crypto.PublicKey, hashed []byte, sig []byte) error {
	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, hashed, sig) {
			return nil
		}
		return errors.New("ecdsa signature verification failed")
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, hashed, sig)
	case ed25519.PublicKey:
		if ed25519.Verify(k, hashed, sig) {
			return nil
		}
		return errors.New("ed25519 signature verification failed")
	default:
		return errors.New("unsupported public key type")
	}
}

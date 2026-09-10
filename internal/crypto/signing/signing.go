package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"fmt"
)

type DecisionSigner struct {
	secret []byte
	issuer string
	keyID  string
}

func NewDecisionSigner(secret []byte, issuer string) *DecisionSigner {
	return NewDecisionSignerWithKeyID(secret, issuer, "v1")
}

func NewDecisionSignerWithKeyID(secret []byte, issuer, keyID string) *DecisionSigner {
	if issuer == "" {
		issuer = "skgate-admission-plane"
	}
	if keyID == "" {
		keyID = "v1"
	}
	return &DecisionSigner{
		secret: secret,
		issuer: issuer,
		keyID:  keyID,
	}
}

func (s *DecisionSigner) Issuer() string {
	return s.issuer
}

func (s *DecisionSigner) KeyID() string {
	return s.keyID
}

func (s *DecisionSigner) Sign(decisionID, artifactDigest, environment, outcome string) string {
	if len(s.secret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%s:%s:%s:%s:%s", s.issuer, decisionID, artifactDigest, environment, outcome)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *DecisionSigner) Verify(decisionID, artifactDigest, environment, outcome, signature string) bool {
	if len(s.secret) == 0 || signature == "" {
		return false
	}
	expected := s.Sign(decisionID, artifactDigest, environment, outcome)
	return hmac.Equal([]byte(signature), []byte(expected))
}

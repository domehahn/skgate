package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestStaticTokenAuth(t *testing.T) {
	auth := NewAuthenticator("secret-token", nil)
	auth.RegisterAPIToken("eval-token", RoleEvaluator)

	role, err := auth.Authenticate("Bearer secret-token")
	if err != nil || role != RoleAdmin {
		t.Fatalf("expected admin role, got %v, err=%v", role, err)
	}

	role, err = auth.Authenticate("Bearer eval-token")
	if err != nil || role != RoleEvaluator {
		t.Fatalf("expected evaluator role, got %v, err=%v", role, err)
	}
}

func TestHMACJWTAuth(t *testing.T) {
	secret := []byte("super-secret-key")
	auth := NewAuthenticator("", secret)

	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	claims := JWTClaims{
		Issuer:  "https://auth.example.com",
		Subject: "workload-1",
		Expiry:  time.Now().Add(time.Hour).Unix(),
		Role:    RolePromoter,
	}

	hBytes, _ := json.Marshal(header)
	cBytes, _ := json.Marshal(claims)
	headB64 := base64.RawURLEncoding.EncodeToString(hBytes)
	claimB64 := base64.RawURLEncoding.EncodeToString(cBytes)

	unsigned := headB64 + "." + claimB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	jwtToken := unsigned + "." + sigB64

	role, err := auth.Authenticate("Bearer " + jwtToken)
	if err != nil || role != RolePromoter {
		t.Fatalf("expected promoter role, got %v, err=%v", role, err)
	}
}

func TestRBACPermissions(t *testing.T) {
	if !HasPermission(RoleAdmin, RolePromoter) {
		t.Fatal("admin should have promoter permission")
	}
	if !HasPermission(RolePromoter, RolePromoter) {
		t.Fatal("promoter should have promoter permission")
	}
	if HasPermission(RoleViewer, RolePromoter) {
		t.Fatal("viewer should not have promoter permission")
	}
}

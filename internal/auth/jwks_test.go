package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestParseJWKS(t *testing.T) {
	// Generate dummy RSA N and E
	nBytes := make([]byte, 128)
	_, _ = rand.Read(nBytes)
	nStr := base64.RawURLEncoding.EncodeToString(nBytes)
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())

	jwksData := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": "key-2026-09",
				"use": "sig",
				"alg": "RS256",
				"n":   nStr,
				"e":   eStr,
			},
		},
	}
	data, _ := json.Marshal(jwksData)

	set, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("expected ParseJWKS to succeed, got %v", err)
	}

	key, ok := set.GetKey("key-2026-09")
	if !ok || key == nil {
		t.Fatal("expected key-2026-09 to be found in JWKSKeySet")
	}

	auth := NewAuthenticator("", nil).WithJWKS(set)
	if _, ok := auth.rsaKeys["key-2026-09"]; !ok {
		t.Fatal("expected key-2026-09 to be registered in Authenticator")
	}
}

func TestRBACHierarchy6Roles(t *testing.T) {
	roles := []Role{RoleAdmin, RoleSecurityReviewer, RoleEvaluator, RolePromoter, RoleAuditor, RoleViewer}

	for _, r := range roles {
		// All roles can view
		if !HasPermission(r, RoleViewer) {
			t.Fatalf("expected role %s to have permission for RoleViewer", r)
		}
	}

	// Admin has permission for all roles
	for _, r := range roles {
		if !HasPermission(RoleAdmin, r) {
			t.Fatalf("expected admin to have permission for %s", r)
		}
	}

	// Security Reviewer permissions
	if !HasPermission(RoleSecurityReviewer, RoleEvaluator) {
		t.Fatal("expected security-reviewer to have permission for evaluator")
	}
	if !HasPermission(RoleSecurityReviewer, RolePromoter) {
		t.Fatal("expected security-reviewer to have permission for promoter")
	}

	// Viewer cannot evaluate or promote
	if HasPermission(RoleViewer, RoleEvaluator) {
		t.Fatal("viewer should not have permission for evaluator")
	}
	if HasPermission(RoleViewer, RolePromoter) {
		t.Fatal("viewer should not have permission for promoter")
	}
}

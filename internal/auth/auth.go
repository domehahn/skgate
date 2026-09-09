package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"

	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Role string

const (
	RoleAdmin     Role = "admin"
	RoleEvaluator Role = "evaluator"
	RolePromoter  Role = "promoter"
	RoleAuditor   Role = "auditor"
	RoleViewer    Role = "viewer"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type JWTClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	Expiry    int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	Role      Role   `json:"role"`
	Roles     []Role `json:"roles,omitempty"`
}

type Authenticator struct {
	apiTokens  map[string]Role
	hmacSecret []byte
	rsaKeys    map[string]*rsa.PublicKey
}

func NewAuthenticator(token string, secret []byte) *Authenticator {
	tokens := make(map[string]Role)
	if token != "" {
		tokens[token] = RoleAdmin
	}
	return &Authenticator{
		apiTokens:  tokens,
		hmacSecret: secret,
		rsaKeys:    make(map[string]*rsa.PublicKey),
	}
}

func (a *Authenticator) RegisterAPIToken(token string, role Role) {
	a.apiTokens[token] = role
}

func (a *Authenticator) RegisterRSAPublicKey(kid string, pubKey *rsa.PublicKey) {
	a.rsaKeys[kid] = pubKey
}

func (a *Authenticator) Authenticate(authHeader string) (Role, error) {
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization header format")
	}
	token := parts[1]

	// 1. Check if token matches static API token
	if role, ok := a.apiTokens[token]; ok {
		return role, nil
	}

	// 2. Try parsing as OIDC JWT token
	claims, err := a.ParseJWT(token)
	if err == nil {
		if claims.Role != "" {
			return claims.Role, nil
		}
		if len(claims.Roles) > 0 {
			return claims.Roles[0], nil
		}
		return RoleViewer, nil
	}

	return "", fmt.Errorf("authentication failed: %w", err)
}

func (a *Authenticator) ParseJWT(tokenStr string) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("decode header failed")
	}
	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("unmarshal header failed")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("decode claims failed")
	}
	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, errors.New("unmarshal claims failed")
	}

	now := time.Now().Unix()
	if claims.Expiry > 0 && now > claims.Expiry {
		return nil, errors.New("token expired")
	}
	if claims.NotBefore > 0 && now < claims.NotBefore {
		return nil, errors.New("token not active")
	}

	signedData := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("decode signature failed")
	}

	switch header.Alg {
	case "HS256":
		if len(a.hmacSecret) == 0 {
			return nil, errors.New("hmac secret not configured")
		}
		mac := hmac.New(sha256.New, a.hmacSecret)
		mac.Write([]byte(signedData))
		expected := mac.Sum(nil)
		if !hmac.Equal(sigBytes, expected) {
			return nil, errors.New("invalid hmac signature")
		}
	case "RS256":
		pubKey, ok := a.rsaKeys[header.Kid]
		if !ok {
			// Try default key if kid not set
			for _, k := range a.rsaKeys {
				pubKey = k
				break
			}
		}
		if pubKey == nil {
			return nil, errors.New("rsa key not found")
		}
		h := sha256.Sum256([]byte(signedData))
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], sigBytes); err != nil {
			return nil, fmt.Errorf("invalid rsa signature: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	return &claims, nil
}

func HasPermission(userRole Role, requiredRole Role) bool {
	if userRole == RoleAdmin {
		return true
	}
	if userRole == requiredRole {
		return true
	}
	// Permissive hierarchy: Evaluator/Promoter/Auditor have Viewer capabilities
	if requiredRole == RoleViewer {
		return true
	}
	return false
}

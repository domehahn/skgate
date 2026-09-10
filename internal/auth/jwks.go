package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWKSKeySet struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func NewJWKSKeySet() *JWKSKeySet {
	return &JWKSKeySet{
		keys: make(map[string]*rsa.PublicKey),
	}
}

func ParseJWKS(data []byte) (*JWKSKeySet, error) {
	var jwks JWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("unmarshal jwks: %w", err)
	}

	set := NewJWKSKeySet()
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.N != "" && key.E != "" {
			pubKey, err := parseRSAPublicKey(key.N, key.E)
			if err == nil {
				set.SetKey(key.Kid, pubKey)
			}
		}
	}
	return set, nil
}

func (s *JWKSKeySet) SetKey(kid string, key *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[kid] = key
}

func (s *JWKSKeySet) GetKey(kid string) (*rsa.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[kid]
	return key, ok
}

func (s *JWKSKeySet) Keys() map[string]*rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]*rsa.PublicKey, len(s.keys))
	for k, v := range s.keys {
		cp[k] = v
	}
	return cp
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	eInt := 0
	for _, b := range eBytes {
		eInt = (eInt << 8) | int(b)
	}

	n := new(big.Int).SetBytes(nBytes)
	return &rsa.PublicKey{
		N: n,
		E: eInt,
	}, nil
}

package trust

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type TrustRoots struct {
	mu                     sync.RWMutex
	FulcioRoots            *x509.CertPool
	RekorKeys              map[string]crypto.PublicKey
	TrustedPublicKeys      map[string]crypto.PublicKey
	GitHubAttestationRoots *x509.CertPool
}

func NewTrustRoots() *TrustRoots {
	return &TrustRoots{
		FulcioRoots:            x509.NewCertPool(),
		RekorKeys:              make(map[string]crypto.PublicKey),
		TrustedPublicKeys:      make(map[string]crypto.PublicKey),
		GitHubAttestationRoots: x509.NewCertPool(),
	}
}

func (tr *TrustRoots) AddFulcioRoot(pemBytes []byte) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.FulcioRoots == nil {
		tr.FulcioRoots = x509.NewCertPool()
	}
	return tr.FulcioRoots.AppendCertsFromPEM(pemBytes)
}

func (tr *TrustRoots) AddGitHubAttestationRoot(pemBytes []byte) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.GitHubAttestationRoots == nil {
		tr.GitHubAttestationRoots = x509.NewCertPool()
	}
	return tr.GitHubAttestationRoots.AppendCertsFromPEM(pemBytes)
}

func (tr *TrustRoots) AddTrustedPublicKey(id string, pemBytes []byte) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	pubKey, err := parsePublicKeyPEM(pemBytes)
	if err != nil {
		return err
	}
	tr.TrustedPublicKeys[id] = pubKey
	return nil
}

func (tr *TrustRoots) GetTrustedPublicKey(id string) (crypto.PublicKey, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	key, ok := tr.TrustedPublicKeys[id]
	return key, ok
}

func LoadFromDir(dir string) (*TrustRoots, error) {
	tr := NewTrustRoots()
	if dir == "" {
		return tr, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return tr, nil
		}
		return nil, fmt.Errorf("read trust root dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		switch {
		case filepath.Ext(entry.Name()) == ".crt" || filepath.Ext(entry.Name()) == ".pem":
			tr.AddFulcioRoot(data)
			tr.AddGitHubAttestationRoot(data)
		case filepath.Ext(entry.Name()) == ".pub" || filepath.Ext(entry.Name()) == ".key":
			_ = tr.AddTrustedPublicKey(entry.Name(), data)
		}
	}
	return tr, nil
}

func parsePublicKeyPEM(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
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

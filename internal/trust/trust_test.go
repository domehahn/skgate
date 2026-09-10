package trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustRoots(t *testing.T) {
	tr := NewTrustRoots()
	if tr == nil {
		t.Fatal("expected NewTrustRoots to return non-nil")
	}

	dir := t.TempDir()
	crtFile := filepath.Join(dir, "root.crt")
	_ = os.WriteFile(crtFile, []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"), 0o600)

	trLoaded, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("expected LoadFromDir to succeed, got %v", err)
	}
	if trLoaded == nil {
		t.Fatal("expected loaded trust roots")
	}
}

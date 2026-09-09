package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func ValidateSHA256(v string) error {
	if !strings.HasPrefix(v, "sha256:") {
		return fmt.Errorf("digest must use sha256:<hex> form")
	}
	raw := strings.TrimPrefix(v, "sha256:")
	if len(raw) != 64 {
		return fmt.Errorf("sha256 digest must contain 64 hex characters")
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return fmt.Errorf("invalid sha256 digest: %w", err)
	}
	return nil
}

func Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

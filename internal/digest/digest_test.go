package digest

import (
	"testing"
)

func TestValidateSHA256(t *testing.T) {
	valid := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := ValidateSHA256(valid); err != nil {
		t.Fatalf("expected valid sha256 to pass, got %v", err)
	}

	invalidPrefix := "md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := ValidateSHA256(invalidPrefix); err == nil {
		t.Fatal("expected error for invalid prefix")
	}

	invalidLength := "sha256:aaaa"
	if err := ValidateSHA256(invalidLength); err == nil {
		t.Fatal("expected error for invalid length")
	}

	invalidHex := "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	if err := ValidateSHA256(invalidHex); err == nil {
		t.Fatal("expected error for invalid hex characters")
	}
}

func TestBytes(t *testing.T) {
	data := []byte("hello world")
	d := Bytes(data)
	if err := ValidateSHA256(d); err != nil {
		t.Fatalf("expected Bytes() output to be valid sha256, got %v", err)
	}
}

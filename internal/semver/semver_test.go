package semver

import (
	"testing"
)

func TestParse(t *testing.T) {
	v, err := Parse("1.2.3")
	if err != nil {
		t.Fatalf("expected Parse to succeed, got %v", err)
	}
	if v.Major != 1 || v.Minor != 2 || v.Patch != 3 {
		t.Fatalf("unexpected version struct: %+v", v)
	}

	v2, err := Parse("v0.6.0-alpha")
	if err != nil {
		t.Fatalf("expected Parse with 'v' and prerelease to succeed, got %v", err)
	}
	if v2.Major != 0 || v2.Minor != 6 || v2.Patch != 0 {
		t.Fatalf("unexpected version struct: %+v", v2)
	}

	if _, err := Parse("invalid"); err == nil {
		t.Fatal("expected error for invalid semver string")
	}
}

func TestCompare(t *testing.T) {
	v1, _ := Parse("1.0.0")
	v2, _ := Parse("1.1.0")
	v3, _ := Parse("1.0.0")

	if Compare(v1, v2) >= 0 {
		t.Fatal("expected 1.0.0 < 1.1.0")
	}
	if Compare(v2, v1) <= 0 {
		t.Fatal("expected 1.1.0 > 1.0.0")
	}
	if Compare(v1, v3) != 0 {
		t.Fatal("expected 1.0.0 == 1.0.0")
	}
}

package store

import (
	"path/filepath"
	"testing"

	"github.com/domehahn/skgate/internal/admission"
)

func TestFileStoreOperations(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	// 1. Decisions
	d := admission.Decision{
		SchemaVersion: "1.0.0",
		DecisionID:    "dec-1",
		Decision:      admission.Allow,
		Subject:       admission.ArtifactSubject{Name: "app", Version: "1.0.0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Environment:   "prod",
	}
	if err := st.SaveDecision(d); err != nil {
		t.Fatalf("SaveDecision failed: %v", err)
	}
	decs, err := st.GetDecisions()
	if err != nil || len(decs) != 1 || decs[0].DecisionID != "dec-1" {
		t.Fatalf("unexpected decisions: %v, err=%v", decs, err)
	}

	// 2. Promotions
	p := Promotion{DecisionID: d.DecisionID, Digest: d.Subject.Digest, Environment: "prod", PromotedBy: "admin", Reason: "approved"}
	if err := st.Promote(p); err != nil {
		t.Fatalf("Promote failed: %v", err)
	}
	proms, err := st.GetPromotions("prod")
	if err != nil || len(proms) != 1 || proms[0].Digest != d.Subject.Digest {
		t.Fatalf("unexpected promotions: %v, err=%v", proms, err)
	}

	// 3. Revocations
	revoked, err := st.IsRevoked(d.Subject.Digest, "prod")
	if err != nil || revoked {
		t.Fatalf("expected not revoked, got %v, err=%v", revoked, err)
	}
	r := Revocation{Digest: d.Subject.Digest, Environment: "prod", RevokedBy: "admin", Reason: "vuln"}
	if err := st.Revoke(r); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	revoked, err = st.IsRevoked(d.Subject.Digest, "prod")
	if err != nil || !revoked {
		t.Fatalf("expected revoked, got %v, err=%v", revoked, err)
	}

	// 4. Backup & Restore
	backupBytes, err := st.Backup()
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	dir2 := filepath.Join(t.TempDir(), "restored")
	st2, err := NewFileStore(dir2)
	if err != nil {
		t.Fatalf("failed to create FileStore 2: %v", err)
	}
	if err := st2.Restore(backupBytes); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	revoked2, err := st2.IsRevoked(d.Subject.Digest, "prod")
	if err != nil || !revoked2 {
		t.Fatalf("restored store should have revocation: %v, err=%v", revoked2, err)
	}
}

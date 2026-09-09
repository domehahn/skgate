package store

import (
	"fmt"
	"sync"
	"testing"

	"github.com/domehahn/skgate/internal/admission"
)

func TestMultiReplicaConsistency(t *testing.T) {
	dir := t.TempDir()

	// Simulate 4 concurrent server node replicas connected to the shared file store
	const numReplicas = 4
	const opsPerReplica = 25

	var replicas []*FileStore
	for i := 0; i < numReplicas; i++ {
		st, err := NewFileStore(dir)
		if err != nil {
			t.Fatalf("failed to create replica %d: %v", i, err)
		}
		replicas = append(replicas, st)
	}

	var wg sync.WaitGroup
	for rIdx := 0; rIdx < numReplicas; rIdx++ {
		wg.Add(1)
		go func(replicaID int) {
			defer wg.Done()
			st := replicas[replicaID]

			for i := 0; i < opsPerReplica; i++ {
				digest := fmt.Sprintf("sha256:%064d", replicaID*1000+i)
				dec := admission.Decision{
					SchemaVersion: "1.0.0",
					DecisionID:    fmt.Sprintf("dec-r%d-%d", replicaID, i),
					Decision:      admission.Allow,
					Subject:       admission.ArtifactSubject{Name: "skill", Version: "1.0.0", Digest: digest},
					Environment:   "production",
				}
				if err := st.SaveDecision(dec); err != nil {
					t.Errorf("replica %d SaveDecision failed: %v", replicaID, err)
				}

				if i%2 == 0 {
					if err := st.Promote(Promotion{Digest: digest, Environment: "production", PromotedBy: "ci"}); err != nil {
						t.Errorf("replica %d Promote failed: %v", replicaID, err)
					}
				}
				if i%5 == 0 {
					if err := st.Revoke(Revocation{Digest: digest, Environment: "production", RevokedBy: "sec"}); err != nil {
						t.Errorf("replica %d Revoke failed: %v", replicaID, err)
					}
				}
			}
		}(rIdx)
	}

	wg.Wait()

	// Verify consistent state across all replicas reading the shared state
	verifier, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("failed to create verifier store: %v", err)
	}

	decs, err := verifier.GetDecisions()
	if err != nil {
		t.Fatalf("GetDecisions failed: %v", err)
	}
	expectedDecs := numReplicas * opsPerReplica
	if len(decs) != expectedDecs {
		t.Fatalf("expected %d decisions across replicas, got %d", expectedDecs, len(decs))
	}

	proms, err := verifier.GetPromotions("production")
	if err != nil {
		t.Fatalf("GetPromotions failed: %v", err)
	}
	if len(proms) == 0 {
		t.Fatalf("expected non-zero promotions")
	}

	revs, err := verifier.GetRevocations("production")
	if err != nil {
		t.Fatalf("GetRevocations failed: %v", err)
	}
	if len(revs) == 0 {
		t.Fatalf("expected non-zero revocations")
	}
}

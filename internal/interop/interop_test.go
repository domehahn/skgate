package interop

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/domehahn/skgate/internal/admission"
	"github.com/domehahn/skgate/internal/api"
	"github.com/domehahn/skgate/internal/auth"
	"github.com/domehahn/skgate/internal/crypto/attestation"
	"github.com/domehahn/skgate/internal/policy"
	"github.com/domehahn/skgate/internal/store"
)

// TestToolchainLifecycleContractUnit tests the local component contract lifecycle unit logic:
// skcr (registry artifact) -> skil (evidence generator) -> skgate (admission check)
// -> skpm (package manager) -> SkillForge (agent builder) -> skgate (admission check)
// -> skpm -> skrun (execution environment)
func TestToolchainLifecycleContractUnit(t *testing.T) {
	pol := policy.Policy{
		SchemaVersion: "1.0.0",
		Name:          "enterprise-production-policy",
		Environments:  []string{"production", "staging"},
		Assurance: policy.AssurancePolicy{
			Provider:        "skil",
			MinimumVersion:  "0.6.0",
			MaximumAge:      "168h",
			RequireComplete: true,
		},
		Signatures: policy.SignaturePolicy{
			Required:          false,
			TrustedIdentities: []string{"github.com/domehahn/skgate/.github/workflows/release.yml"},
		},
		Capabilities: policy.CapabilityPolicy{
			Deny:             []string{"unrestricted_network"},
			ApprovalRequired: []string{"filesystem_write"},
		},
		Provenance: policy.ProvenancePolicy{Required: true},
		Risk:       policy.RiskPolicy{Maximum: "medium"},
		Runtime: policy.RuntimePolicy{
			AllowedCommands:     []string{"git", "go"},
			AllowWorkspaceWrite: false,
			AllowNetwork:        false,
			TimeoutSeconds:      120,
			MaxOutputBytes:      1048576,
		},
	}

	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	srv := api.New(admission.New(pol), st, "skgate-token-prod", true, nil)
	srv.WithAuthenticator(auth.NewAuthenticator("skgate-token-prod", nil))
	handler := srv.Handler()

	artifactDigest := "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	now := time.Now().UTC()

	// Step 1: Stage 1 Admission (skcr -> skil -> skgate)
	evalReqStage1 := admission.EvaluationRequest{
		Subject: admission.ArtifactSubject{
			Name:    "governed-skill",
			Version: "1.0.0",
			Digest:  artifactDigest,
		},
		Environment: "staging",
		Evidence: admission.Evidence{
			SchemaVersion:   "1.0.0",
			SubjectDigest:   artifactDigest,
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			CompletedAt:     now,
			Complete:        true,
			Passed:          true,
			Risk:            "low",
			Capabilities:    []string{"filesystem_read"},
			GitHubAttestation: &attestation.GitHubAttestation{
				PredicateType: "https://slsa.dev/provenance/v1",
				SubjectDigest: artifactDigest,
				Repository:    "github.com/domehahn/skgate",
			},
		},
	}
	evalReqStage1.Evidence.GitHubAttestation.Builder.ID = "https://github.com/actions/runner"

	body1, _ := json.Marshal(evalReqStage1)
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body1))
	req1.Header.Set("Authorization", "Bearer skgate-token-prod")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("Stage 1 evaluation failed with status %d: %s", rec1.Code, rec1.Body.String())
	}

	var decStage1 admission.Decision
	_ = json.Unmarshal(rec1.Body.Bytes(), &decStage1)
	if decStage1.Decision != admission.Allow {
		t.Fatalf("expected ALLOW for Stage 1, got %s reasons=%v", decStage1.Decision, decStage1.Reasons)
	}

	// Step 2: Promotion (skpm -> SkillForge -> promote to production bound to decision_id)
	promoReq := store.Promotion{
		DecisionID:  decStage1.DecisionID,
		Digest:      artifactDigest,
		Environment: "staging",
		PromotedBy:  "SkillForge-CI",
		Reason:      "Automated pipeline verification passed",
	}
	bodyPromo, _ := json.Marshal(promoReq)
	reqPromo := httptest.NewRequest(http.MethodPost, "/api/v1/promotions", bytes.NewReader(bodyPromo))
	reqPromo.Header.Set("Authorization", "Bearer skgate-token-prod")
	recPromo := httptest.NewRecorder()
	handler.ServeHTTP(recPromo, reqPromo)

	if recPromo.Code != http.StatusCreated {
		t.Fatalf("Promotion failed with status %d: %s", recPromo.Code, recPromo.Body.String())
	}

	// Step 3: Production Admission (skgate -> skpm -> skrun)
	evalReqStage2 := evalReqStage1
	evalReqStage2.Environment = "production"

	body2, _ := json.Marshal(evalReqStage2)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer skgate-token-prod")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Stage 2 evaluation failed with status %d: %s", rec2.Code, rec2.Body.String())
	}

	var decStage2 admission.Decision
	_ = json.Unmarshal(rec2.Body.Bytes(), &decStage2)
	if decStage2.Decision != admission.Allow {
		t.Fatalf("expected ALLOW for Stage 2, got %s", decStage2.Decision)
	}
	if decStage2.RuntimePolicy == nil || decStage2.RuntimePolicy.ArtifactDigest != artifactDigest {
		t.Fatalf("expected effective runtime policy bound to digest %s", artifactDigest)
	}

	// Step 4: Emergency Revocation (Security Event)
	revReq := store.Revocation{
		Digest:      artifactDigest,
		Environment: "production",
		RevokedBy:   "Security-SecOps",
		Reason:      "CVE-2026-9999 emergency revocation",
	}
	bodyRev, _ := json.Marshal(revReq)
	reqRev := httptest.NewRequest(http.MethodPost, "/api/v1/revocations", bytes.NewReader(bodyRev))
	reqRev.Header.Set("Authorization", "Bearer skgate-token-prod")
	recRev := httptest.NewRecorder()
	handler.ServeHTTP(recRev, reqRev)

	if recRev.Code != http.StatusCreated {
		t.Fatalf("Revocation failed with status %d", recRev.Code)
	}

	// Step 5: Post-revocation Admission Check must fail closed (DENY)
	body3, _ := json.Marshal(evalReqStage2)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body3))
	req3.Header.Set("Authorization", "Bearer skgate-token-prod")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	var decStage3 admission.Decision
	_ = json.Unmarshal(rec3.Body.Bytes(), &decStage3)
	if decStage3.Decision != admission.Deny {
		t.Fatalf("expected DENY after revocation, got %s", decStage3.Decision)
	}

	// Step 6: Quarantine API verification
	quarReq := store.Quarantine{
		Digest:        artifactDigest,
		Environment:   "production",
		QuarantinedBy: "SecOps",
		Reason:        "Active incident isolation",
		IncidentID:    "INC-2026-001",
	}
	bodyQuar, _ := json.Marshal(quarReq)
	reqQuar := httptest.NewRequest(http.MethodPost, "/api/v1/quarantines", bytes.NewReader(bodyQuar))
	reqQuar.Header.Set("Authorization", "Bearer skgate-token-prod")
	recQuar := httptest.NewRecorder()
	handler.ServeHTTP(recQuar, reqQuar)

	if recQuar.Code != http.StatusCreated {
		t.Fatalf("Quarantine API failed with status %d: %s", recQuar.Code, recQuar.Body.String())
	}

	// Step 7: Unquarantine API verification
	reqUnquar := httptest.NewRequest(http.MethodDelete, "/api/v1/quarantines?id="+artifactDigest, nil)
	reqUnquar.Header.Set("Authorization", "Bearer skgate-token-prod")
	recUnquar := httptest.NewRecorder()
	handler.ServeHTTP(recUnquar, reqUnquar)

	if recUnquar.Code != http.StatusOK {
		t.Fatalf("Unquarantine API failed with status %d: %s", recUnquar.Code, recUnquar.Body.String())
	}
}

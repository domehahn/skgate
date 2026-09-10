package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/domehahn/skgate/internal/admission"
	"github.com/domehahn/skgate/internal/auth"
	"github.com/domehahn/skgate/internal/policy"
	"github.com/domehahn/skgate/internal/store"
)

func TestProductionRequiresAuth(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: "1.0.0",
		Name:          "p",
		Environments:  []string{"prod"},
		Assurance:     policy.AssurancePolicy{Provider: "skil", MinimumVersion: "0.6.0"},
		Risk:          policy.RiskPolicy{Maximum: "low"},
		Runtime:       policy.RuntimePolicy{TimeoutSeconds: 1, MaxOutputBytes: 1},
	}
	st, _ := store.NewFileStore(t.TempDir())
	s := New(admission.New(p), st, "", true, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestPromotionAndRevocationAPIs(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: "1.0.0",
		Name:          "p",
		Environments:  []string{"prod"},
		Assurance:     policy.AssurancePolicy{Provider: "skil", MinimumVersion: "0.6.0"},
		Risk:          policy.RiskPolicy{Maximum: "low"},
		Runtime:       policy.RuntimePolicy{TimeoutSeconds: 1, MaxOutputBytes: 1},
	}
	st, _ := store.NewFileStore(t.TempDir())
	s := New(admission.New(p), st, "admin-token", true, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	s.authenticator.RegisterAPIToken("promo-token", auth.RolePromoter)

	// 0. Perform valid ALLOW evaluation first
	evalReq := admission.EvaluationRequest{
		Subject: admission.ArtifactSubject{
			Name:    "skill",
			Version: "1.0.0",
			Digest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Environment: "prod",
		Evidence: admission.Evidence{
			SubjectDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Provider:        "skil",
			ProviderVersion: "0.6.0",
			Passed:          true,
			Complete:        true,
			Risk:            "low",
		},
	}
	bEval, _ := json.Marshal(evalReq)
	reqEval := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(bEval))
	reqEval.Header.Set("Authorization", "Bearer admin-token")
	rrEval := httptest.NewRecorder()
	s.Handler().ServeHTTP(rrEval, reqEval)

	var dec admission.Decision
	_ = json.Unmarshal(rrEval.Body.Bytes(), &dec)
	if dec.Decision != admission.Allow {
		t.Fatalf("expected initial evaluation ALLOW, got %s", dec.Decision)
	}

	// 1. Promote digest bound to decision_id
	promoReq := store.Promotion{
		DecisionID:  dec.DecisionID,
		Digest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Environment: "prod",
		PromotedBy:  "alice",
		Reason:      "approved release",
	}
	b, _ := json.Marshal(promoReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/promotions", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer promo-token")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d body=%s", rr.Code, rr.Body.String())
	}

	// 2. Revoke digest
	revReq := store.Revocation{
		Digest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Environment: "prod",
		RevokedBy:   "security-team",
		Reason:      "security issue",
	}
	b2, _ := json.Marshal(revReq)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/revocations", bytes.NewReader(b2))
	req2.Header.Set("Authorization", "Bearer admin-token")
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d body=%s", rr2.Code, rr2.Body.String())
	}

	// 3. Verify Revocation causes subsequent evaluation DENY
	b3, _ := json.Marshal(evalReq)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(b3))
	req3.Header.Set("Authorization", "Bearer admin-token")
	rr3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr3, req3)

	var dec3 admission.Decision
	_ = json.Unmarshal(rr3.Body.Bytes(), &dec3)
	if dec3.Decision != admission.Deny {
		t.Fatalf("expected DENY for revoked artifact, got %s", dec3.Decision)
	}
}

func TestReadyzHealthProbe(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: "1.0.0",
		Name:          "p",
		Environments:  []string{"prod"},
		Assurance:     policy.AssurancePolicy{Provider: "skil", MinimumVersion: "0.6.0"},
		Risk:          policy.RiskPolicy{Maximum: "low"},
		Runtime:       policy.RuntimePolicy{TimeoutSeconds: 1, MaxOutputBytes: 1},
	}
	st, _ := store.NewFileStore(t.TempDir())
	s := New(admission.New(p), st, "admin-token", true, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /readyz, got %d body=%s", rr.Code, rr.Body.String())
	}
}

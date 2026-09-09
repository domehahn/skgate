package admission

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/domehahn/skgate/internal/crypto/attestation"
	"github.com/domehahn/skgate/internal/digest"
	"github.com/domehahn/skgate/internal/policy"
	"github.com/domehahn/skgate/internal/semver"
)

const (
	Allow            = "ALLOW"
	Deny             = "DENY"
	ReviewRequired   = "REVIEW_REQUIRED"
	ReassessRequired = "REASSESS_REQUIRED"
)

type RevocationChecker interface {
	IsRevoked(digest, env string) (bool, error)
}

type Evaluator struct {
	Policy      policy.Policy
	Revocations RevocationChecker
	Now         func() time.Time
	Verifier    *attestation.Verifier
}

func New(p policy.Policy) Evaluator {
	return Evaluator{
		Policy:   p,
		Now:      time.Now,
		Verifier: attestation.NewVerifier(),
	}
}

func (e Evaluator) WithRevocations(rc RevocationChecker) Evaluator {
	e.Revocations = rc
	return e
}

func (e Evaluator) Evaluate(req EvaluationRequest) Decision {
	now := e.Now().UTC()
	d := Decision{
		SchemaVersion: DecisionSchemaVersion,
		DecisionID:    newID(),
		Subject:       req.Subject,
		Environment:   req.Environment,
		PolicyName:    e.Policy.Name,
		PolicyDigest:  policyDigest(e.Policy),
		EvaluatedAt:   now,
		Decision:      Allow,
	}
	deny := func(code, msg string) { d.Decision = Deny; d.Reasons = append(d.Reasons, Reason{code, msg}) }
	review := func(code, msg string) {
		if d.Decision != Deny {
			d.Decision = ReviewRequired
		}
		d.Reasons = append(d.Reasons, Reason{code, msg})
	}
	reassess := func(code, msg string) {
		if d.Decision != Deny && d.Decision != ReviewRequired {
			d.Decision = ReassessRequired
		}
		d.Reasons = append(d.Reasons, Reason{code, msg})
	}

	if err := digest.ValidateSHA256(req.Subject.Digest); err != nil {
		deny("SKGATE-SUBJECT-DIGEST-INVALID", err.Error())
	}
	if req.Evidence.SubjectDigest != req.Subject.Digest {
		deny("SKGATE-EVIDENCE-SUBJECT-MISMATCH", "evidence is not bound to the requested artifact digest")
	}

	// Check Revocation Status - FAIL CLOSED if storage/lookup fails
	if e.Revocations != nil {
		revoked, err := e.Revocations.IsRevoked(req.Subject.Digest, req.Environment)
		if err != nil {
			deny("SKGATE-REVOCATION-STATE-UNAVAILABLE", fmt.Sprintf("cannot determine revocation status: %v", err))
		} else if revoked {
			deny("SKGATE-DIGEST-REVOKED", "artifact digest has been revoked for this environment")
		}
	}

	if !e.Policy.SupportsEnvironment(req.Environment) {
		deny("SKGATE-ENVIRONMENT-DENIED", "policy does not apply to requested environment")
	}
	if req.Evidence.Provider != e.Policy.Assurance.Provider {
		deny("SKGATE-ASSURANCE-PROVIDER", "required assurance provider is missing")
	}
	minv, _ := semver.Parse(e.Policy.Assurance.MinimumVersion)
	gotv, err := semver.Parse(req.Evidence.ProviderVersion)
	if err != nil || semver.Compare(gotv, minv) < 0 {
		reassess("SKGATE-ASSURANCE-VERSION", fmt.Sprintf("assurance provider must be >= %s", e.Policy.Assurance.MinimumVersion))
	}
	if e.Policy.Assurance.RequireComplete && !req.Evidence.Complete {
		deny("SKGATE-ASSURANCE-INCOMPLETE", "required assurance evidence is incomplete")
	}
	if !req.Evidence.Passed {
		deny("SKGATE-ASSURANCE-FAILED", "assurance evidence did not pass")
	}
	if e.Policy.Assurance.MaximumAge != "" {
		maxAge, _ := time.ParseDuration(e.Policy.Assurance.MaximumAge)
		if req.Evidence.CompletedAt.IsZero() || now.Sub(req.Evidence.CompletedAt) > maxAge {
			reassess("SKGATE-ASSURANCE-STALE", "assurance evidence is older than policy allows")
		}
	}

	// Signature verification: Require real cryptographic evidence payloads inside trust boundary
	if e.Policy.Signatures.Required {
		if req.Evidence.SigstoreBundle != nil {
			if err := e.Verifier.VerifySigstore(*req.Evidence.SigstoreBundle, req.Subject.Digest, e.Policy.Signatures.TrustedIdentities); err != nil {
				deny("SKGATE-SIGSTORE-INVALID", err.Error())
			}
		} else if req.Evidence.DSSEEnvelope != nil && len(e.Policy.Signatures.TrustedIdentities) > 0 {
			if err := e.Verifier.VerifyDSSE(*req.Evidence.DSSEEnvelope, e.Policy.Signatures.TrustedIdentities[0]); err != nil {
				deny("SKGATE-DSSE-INVALID", err.Error())
			}
		} else {
			deny("SKGATE-SIGNATURE-UNVERIFIED", "signature verification requires valid cryptographic payload (SigstoreBundle or DSSEEnvelope)")
		}
	}

	// Provenance verification: Require real cryptographic attestation payloads inside trust boundary
	if e.Policy.Provenance.Required {
		if req.Evidence.GitHubAttestation != nil {
			if err := e.Verifier.VerifyGitHubAttestation(*req.Evidence.GitHubAttestation, req.Subject.Digest); err != nil {
				deny("SKGATE-PROVENANCE-INVALID", err.Error())
			}
		} else if req.Evidence.DSSEEnvelope != nil {
			// DSSE in-toto provenance statement payload
			if req.Evidence.DSSEEnvelope.PayloadType != "application/vnd.in-toto+json" {
				deny("SKGATE-PROVENANCE-INVALID", "dsse envelope payloadType must be application/vnd.in-toto+json")
			}
		} else {
			deny("SKGATE-PROVENANCE-UNVERIFIED", "provenance verification requires valid cryptographic attestation payload (GitHubAttestation or DSSEEnvelope)")
		}
	}

	if riskRank(req.Evidence.Risk) > riskRank(e.Policy.Risk.Maximum) {
		deny("SKGATE-RISK-TOO-HIGH", fmt.Sprintf("risk %s exceeds maximum %s", req.Evidence.Risk, e.Policy.Risk.Maximum))
	}
	for _, cap := range req.Evidence.Capabilities {
		if slices.Contains(e.Policy.Capabilities.Deny, cap) {
			deny("SKGATE-CAPABILITY-DENIED", "capability denied by policy: "+cap)
		}
		if slices.Contains(e.Policy.Capabilities.ApprovalRequired, cap) && !slices.Contains(req.Approvals, cap) {
			review("SKGATE-APPROVAL-REQUIRED", "approval required for capability: "+cap)
		}
	}
	if d.Decision == Allow {
		d.RuntimePolicy = &RuntimePolicy{
			SchemaVersion:       "1.0.0",
			ArtifactDigest:      req.Subject.Digest,
			AllowedCommands:     append([]string(nil), e.Policy.Runtime.AllowedCommands...),
			AllowedSecrets:      append([]string(nil), e.Policy.Runtime.AllowedSecrets...),
			AllowWorkspaceWrite: e.Policy.Runtime.AllowWorkspaceWrite,
			AllowNetwork:        e.Policy.Runtime.AllowNetwork,
			TimeoutSeconds:      e.Policy.Runtime.TimeoutSeconds,
			MaxOutputBytes:      e.Policy.Runtime.MaxOutputBytes,
		}
	}
	if len(d.Reasons) == 0 {
		d.Reasons = []Reason{{Code: "SKGATE-ALLOW", Message: "all admission requirements satisfied"}}
	}
	return d
}

func riskRank(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 99
	}
}

func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("decision-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func policyDigest(p policy.Policy) string {
	b, _ := json.Marshal(p)
	return digest.Bytes(b)
}

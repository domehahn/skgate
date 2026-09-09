package admission

import (
	"time"

	"github.com/domehahn/skgate/internal/crypto/attestation"
)

const DecisionSchemaVersion = "1.0.0"

type ArtifactSubject struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type Evidence struct {
	SchemaVersion      string    `json:"schema_version"`
	SubjectDigest      string    `json:"subject_digest"`
	Provider           string    `json:"provider"`
	ProviderVersion    string    `json:"provider_version"`
	CompletedAt        time.Time `json:"completed_at"`
	Complete           bool      `json:"complete"`
	Passed             bool      `json:"passed"`
	SignatureVerified  bool      `json:"signature_verified"`
	SignerIdentity     string    `json:"signer_identity"`
	ProvenanceVerified bool      `json:"provenance_verified"`
	Risk               string    `json:"risk"`
	Capabilities       []string  `json:"capabilities"`

	// Cryptographic Envelope Payload (Optional)
	DSSEEnvelope      *attestation.DSSEEnvelope      `json:"dsse_envelope,omitempty"`
	SigstoreBundle    *attestation.SigstoreBundle    `json:"sigstore_bundle,omitempty"`
	GitHubAttestation *attestation.GitHubAttestation `json:"github_attestation,omitempty"`
}

type EvaluationRequest struct {
	Subject     ArtifactSubject `json:"subject"`
	Environment string          `json:"environment"`
	Evidence    Evidence        `json:"evidence"`
	Approvals   []string        `json:"approvals"`
}

type RuntimePolicy struct {
	SchemaVersion       string   `json:"schema_version"`
	ArtifactDigest      string   `json:"artifact_digest"`
	AllowedCommands     []string `json:"allowed_commands"`
	AllowedSecrets      []string `json:"allowed_secrets"`
	AllowWorkspaceWrite bool     `json:"allow_workspace_write"`
	AllowNetwork        bool     `json:"allow_network"`
	TimeoutSeconds      int      `json:"timeout_seconds"`
	MaxOutputBytes      int64    `json:"max_output_bytes"`
}

type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Decision struct {
	SchemaVersion string          `json:"schema_version"`
	DecisionID    string          `json:"decision_id"`
	Decision      string          `json:"decision"`
	Subject       ArtifactSubject `json:"subject"`
	Environment   string          `json:"environment"`
	PolicyName    string          `json:"policy_name"`
	PolicyDigest  string          `json:"policy_digest"`
	EvaluatedAt   time.Time       `json:"evaluated_at"`
	Reasons       []Reason        `json:"reasons"`
	RuntimePolicy *RuntimePolicy  `json:"runtime_policy,omitempty"`
}

package admission

import (
	"time"

	"github.com/domehahn/skgate/internal/crypto/attestation"
)

const DecisionSchemaVersion = "1.0.0"

type EvidenceStatus string

const (
	EvidencePass       EvidenceStatus = "PASS"
	EvidenceFail       EvidenceStatus = "FAIL"
	EvidenceUnknown    EvidenceStatus = "UNKNOWN"
	EvidenceIncomplete EvidenceStatus = "INCOMPLETE"
	EvidenceStale      EvidenceStatus = "STALE"
)

type ArtifactSubject struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type Evidence struct {
	SchemaVersion      string         `json:"schema_version"`
	SubjectDigest      string         `json:"subject_digest"`
	EvidenceDigest     string         `json:"evidence_digest,omitempty"`
	Status             EvidenceStatus `json:"status,omitempty"`
	Provider           string         `json:"provider"`
	ProviderVersion    string         `json:"provider_version"`
	CompletedAt        time.Time      `json:"completed_at"`
	Complete           bool           `json:"complete"`
	Passed             bool           `json:"passed"`
	SignatureVerified  bool           `json:"signature_verified,omitempty"`
	SignerIdentity     string         `json:"signer_identity,omitempty"`
	ProvenanceVerified bool           `json:"provenance_verified,omitempty"`
	Risk               string         `json:"risk"`
	Capabilities       []string       `json:"capabilities"`

	// Cryptographic Evidence Payloads (Required for Production Verification)
	DSSEEnvelope      *attestation.DSSEEnvelope      `json:"dsse_envelope,omitempty"`
	SigstoreBundle    *attestation.SigstoreBundle    `json:"sigstore_bundle,omitempty"`
	GitHubAttestation *attestation.GitHubAttestation `json:"github_attestation,omitempty"`
}

type ApprovalRecord struct {
	ApprovalID    string    `json:"approval_id"`
	SubjectDigest string    `json:"subject_digest"`
	Environment   string    `json:"environment,omitempty"`
	Capability    string    `json:"capability"`
	ApprovedBy    string    `json:"approved_by"`
	ApprovedAt    time.Time `json:"approved_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	PolicyDigest  string    `json:"policy_digest,omitempty"`
	Signature     string    `json:"signature,omitempty"`
}

type EvaluationRequest struct {
	Subject         ArtifactSubject  `json:"subject"`
	Environment     string           `json:"environment"`
	Evidence        Evidence         `json:"evidence"`
	Approvals       []string         `json:"approvals,omitempty"`
	ApprovalRecords []ApprovalRecord `json:"approval_records,omitempty"`
}

type EgressRule struct {
	Domain string `json:"domain"`
	Port   int    `json:"port"`
}

type FilesystemConstraints struct {
	AllowWrite   bool     `json:"allow_write"`
	AllowedPaths []string `json:"allowed_paths,omitempty"`
}

type NetworkConstraints struct {
	AllowNetwork  bool         `json:"allow_network"`
	AllowedEgress []EgressRule `json:"allowed_egress,omitempty"`
}

type ResourceLimits struct {
	MaxMemoryMB    int64   `json:"max_memory_mb"`
	MaxCPUs        float64 `json:"max_cpus"`
	MaxPIDs        int     `json:"max_pids"`
	MaxFDs         int     `json:"max_fds"`
	TimeoutSeconds int     `json:"timeout_seconds"`
	MaxOutputBytes int64   `json:"max_output_bytes"`
}

type RuntimePolicy struct {
	SchemaVersion     string                `json:"schema_version"`
	ArtifactDigest    string                `json:"artifact_digest"`
	DecisionID        string                `json:"decision_id"`
	Environment       string                `json:"environment"`
	PolicyDigest      string                `json:"policy_digest"`
	IssuedAt          time.Time             `json:"issued_at"`
	ExpiresAt         time.Time             `json:"expires_at"`
	AllowedCommands   []string              `json:"allowed_commands"`
	Filesystem        FilesystemConstraints `json:"filesystem"`
	Network           NetworkConstraints    `json:"network"`
	AllowedSecrets    []string              `json:"allowed_secrets"`
	AllowedTools      []string              `json:"allowed_tools"`
	AllowedMCPServers []string              `json:"allowed_mcp_servers"`
	ResourceLimits    ResourceLimits        `json:"resource_limits"`
}

type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Decision struct {
	SchemaVersion  string          `json:"schema_version"`
	DecisionID     string          `json:"decision_id"`
	Decision       string          `json:"decision"`
	Subject        ArtifactSubject `json:"subject"`
	Environment    string          `json:"environment"`
	PolicyName     string          `json:"policy_name"`
	PolicyDigest   string          `json:"policy_digest"`
	EvidenceDigest string          `json:"evidence_digest,omitempty"`
	EvaluatedAt    time.Time       `json:"evaluated_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Issuer         string          `json:"issuer,omitempty"`
	KeyID          string          `json:"key_id,omitempty"`
	Signature      string          `json:"signature,omitempty"`
	Reasons        []Reason        `json:"reasons"`
	RuntimePolicy  *RuntimePolicy  `json:"runtime_policy,omitempty"`
}

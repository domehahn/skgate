package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/domehahn/skgate/internal/semver"
)

const SchemaVersion = "1.0.0"

type Policy struct {
	SchemaVersion string           `json:"schema_version"`
	Name          string           `json:"name"`
	Environments  []string         `json:"environments"`
	Assurance     AssurancePolicy  `json:"assurance"`
	Signatures    SignaturePolicy  `json:"signatures"`
	Capabilities  CapabilityPolicy `json:"capabilities"`
	Provenance    ProvenancePolicy `json:"provenance"`
	Risk          RiskPolicy       `json:"risk"`
	Runtime       RuntimePolicy    `json:"runtime"`
}

type AssurancePolicy struct {
	Provider        string `json:"provider"`
	MinimumVersion  string `json:"minimum_version"`
	MaximumAge      string `json:"maximum_age"`
	RequireComplete bool   `json:"require_complete"`
}

type SignaturePolicy struct {
	Required          bool     `json:"required"`
	TrustedIdentities []string `json:"trusted_identities"`
}

type CapabilityPolicy struct {
	Deny             []string `json:"deny"`
	ApprovalRequired []string `json:"approval_required"`
}

type ProvenancePolicy struct {
	Required bool `json:"required"`
}
type RiskPolicy struct {
	Maximum string `json:"maximum"`
}

type RuntimePolicy struct {
	AllowedCommands     []string `json:"allowed_commands"`
	AllowedSecrets      []string `json:"allowed_secrets"`
	AllowWorkspaceWrite bool     `json:"allow_workspace_write"`
	AllowNetwork        bool     `json:"allow_network"`
	TimeoutSeconds      int      `json:"timeout_seconds"`
	MaxOutputBytes      int64    `json:"max_output_bytes"`
}

func Load(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported policy schema_version %q", p.SchemaVersion)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("policy name is required")
	}
	if len(p.Environments) == 0 {
		return fmt.Errorf("at least one environment is required")
	}
	if p.Assurance.Provider == "" {
		return fmt.Errorf("assurance.provider is required")
	}
	if _, err := semver.Parse(p.Assurance.MinimumVersion); err != nil {
		return fmt.Errorf("assurance.minimum_version: %w", err)
	}
	if p.Assurance.MaximumAge != "" {
		if _, err := time.ParseDuration(p.Assurance.MaximumAge); err != nil {
			return fmt.Errorf("assurance.maximum_age: %w", err)
		}
	}
	validRisk := []string{"low", "medium", "high", "critical"}
	if !slices.Contains(validRisk, strings.ToLower(p.Risk.Maximum)) {
		return fmt.Errorf("risk.maximum must be low, medium, high, or critical")
	}
	if p.Signatures.Required && len(p.Signatures.TrustedIdentities) == 0 {
		return fmt.Errorf("trusted_identities required when signatures.required=true")
	}
	if p.Runtime.TimeoutSeconds <= 0 {
		return fmt.Errorf("runtime.timeout_seconds must be > 0")
	}
	if p.Runtime.MaxOutputBytes <= 0 {
		return fmt.Errorf("runtime.max_output_bytes must be > 0")
	}
	return nil
}

func (p Policy) SupportsEnvironment(env string) bool { return slices.Contains(p.Environments, env) }

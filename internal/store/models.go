package store

import (
	"time"

	"github.com/domehahn/skgate/internal/admission"
)

type Promotion struct {
	ID          string    `json:"id"`
	DecisionID  string    `json:"decision_id"`
	Digest      string    `json:"digest"`
	Environment string    `json:"environment"`
	PromotedBy  string    `json:"promoted_by"`
	PromotedAt  time.Time `json:"promoted_at"`
	Reason      string    `json:"reason,omitempty"`
}

type Revocation struct {
	ID          string     `json:"id"`
	Digest      string     `json:"digest"`
	Environment string     `json:"environment"`
	RevokedBy   string     `json:"revoked_by"`
	RevokedAt   time.Time  `json:"revoked_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	IncidentID  string     `json:"incident_id,omitempty"`
}

type Quarantine struct {
	ID            string    `json:"id"`
	Digest        string    `json:"digest"`
	Environment   string    `json:"environment"`
	QuarantinedBy string    `json:"quarantined_by"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	Reason        string    `json:"reason,omitempty"`
	IncidentID    string    `json:"incident_id,omitempty"`
}

type BackupData struct {
	SchemaVersion string               `json:"schema_version"`
	ExportedAt    time.Time            `json:"exported_at"`
	Decisions     []admission.Decision `json:"decisions"`
	Promotions    []Promotion          `json:"promotions"`
	Revocations   []Revocation         `json:"revocations"`
	Quarantines   []Quarantine         `json:"quarantines"`
}

type Store interface {
	Ping() error

	SaveDecision(d admission.Decision) error
	GetDecisions() ([]admission.Decision, error)

	Promote(p Promotion) error
	GetPromotions(env string) ([]Promotion, error)

	Revoke(r Revocation) error
	GetRevocations(env string) ([]Revocation, error)
	IsRevoked(digest, env string) (bool, error)

	Quarantine(q Quarantine) error
	GetQuarantines(env string) ([]Quarantine, error)
	IsQuarantined(digest, env string) (bool, error)
	Unquarantine(id string) error

	Backup() ([]byte, error)
	Restore(data []byte) error
}

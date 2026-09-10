package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/domehahn/skgate/internal/admission"
)

type SQLStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(15 * time.Minute)

	if err := Migrate(db); err != nil {
		return nil, fmt.Errorf("run schema migrations: %w", err)
	}
	return &SQLStore{db: db}, nil
}

func (s *SQLStore) Ping() error {
	return s.db.Ping()
}

func (s *SQLStore) SaveDecision(d admission.Decision) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	query := `
INSERT INTO decisions (decision_id, schema_version, decision, subject_name, subject_version, subject_digest, environment, policy_name, policy_digest, evaluated_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (decision_id) DO NOTHING`
	_, err = s.db.Exec(query, d.DecisionID, d.SchemaVersion, d.Decision, d.Subject.Name, d.Subject.Version, d.Subject.Digest, d.Environment, d.PolicyName, d.PolicyDigest, d.EvaluatedAt.UTC(), string(b))
	return err
}

func (s *SQLStore) GetDecisions() ([]admission.Decision, error) {
	rows, err := s.db.Query("SELECT data FROM decisions ORDER BY evaluated_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []admission.Decision
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var d admission.Decision
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return nil, err
		}
		list = append(list, d)
	}
	return list, rows.Err()
}

func (s *SQLStore) Promote(p Promotion) error {
	if p.DecisionID == "" {
		return fmt.Errorf("promotion requires a valid decision_id proving prior ALLOW admission decision")
	}

	var decRaw string
	err := s.db.QueryRow("SELECT data FROM decisions WHERE decision_id = $1", p.DecisionID).Scan(&decRaw)
	if err == sql.ErrNoRows {
		return fmt.Errorf("decision_id %q not found in decision store", p.DecisionID)
	}
	if err != nil {
		return fmt.Errorf("query decision_id: %w", err)
	}

	var d admission.Decision
	if err := json.Unmarshal([]byte(decRaw), &d); err != nil {
		return fmt.Errorf("unmarshal decision data: %w", err)
	}

	if d.Decision != admission.Allow {
		return fmt.Errorf("decision_id %q is %s, promotion requires ALLOW decision", p.DecisionID, d.Decision)
	}
	if d.Subject.Digest != p.Digest {
		return fmt.Errorf("decision digest %s mismatch promotion digest %s", d.Subject.Digest, p.Digest)
	}
	if d.Environment != p.Environment {
		return fmt.Errorf("decision environment %s mismatch promotion environment %s", d.Environment, p.Environment)
	}
	if !d.ExpiresAt.IsZero() && time.Now().After(d.ExpiresAt) {
		return fmt.Errorf("decision_id %q has expired at %s", p.DecisionID, d.ExpiresAt.Format(time.RFC3339))
	}

	revoked, err := s.IsRevoked(p.Digest, p.Environment)
	if err != nil {
		return fmt.Errorf("check revocation for promotion: %w", err)
	}
	if revoked {
		return fmt.Errorf("digest %s is revoked in environment %q, promotion denied", p.Digest, p.Environment)
	}

	quarantined, err := s.IsQuarantined(p.Digest, p.Environment)
	if err != nil {
		return fmt.Errorf("check quarantine for promotion: %w", err)
	}
	if quarantined {
		return fmt.Errorf("digest %s is quarantined in environment %q, promotion denied", p.Digest, p.Environment)
	}

	if p.ID == "" {
		p.ID = newID("promo")
	}
	if p.PromotedAt.IsZero() {
		p.PromotedAt = time.Now().UTC()
	}
	query := `INSERT INTO promotions (id, decision_id, digest, environment, promoted_by, promoted_at, reason) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.db.Exec(query, p.ID, p.DecisionID, p.Digest, p.Environment, p.PromotedBy, p.PromotedAt.UTC(), p.Reason)
	return err
}

func (s *SQLStore) GetPromotions(env string) ([]Promotion, error) {
	var rows *sql.Rows
	var err error
	if env == "" {
		rows, err = s.db.Query("SELECT id, COALESCE(decision_id, ''), digest, environment, promoted_by, promoted_at, COALESCE(reason, '') FROM promotions ORDER BY promoted_at ASC")
	} else {
		rows, err = s.db.Query("SELECT id, COALESCE(decision_id, ''), digest, environment, promoted_by, promoted_at, COALESCE(reason, '') FROM promotions WHERE environment = $1 ORDER BY promoted_at ASC", env)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Promotion
	for rows.Next() {
		var p Promotion
		if err := rows.Scan(&p.ID, &p.DecisionID, &p.Digest, &p.Environment, &p.PromotedBy, &p.PromotedAt, &p.Reason); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func (s *SQLStore) Revoke(r Revocation) error {
	if r.ID == "" {
		r.ID = newID("rev")
	}
	if r.RevokedAt.IsZero() {
		r.RevokedAt = time.Now().UTC()
	}
	query := `INSERT INTO revocations (id, digest, environment, revoked_by, revoked_at, reason) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.db.Exec(query, r.ID, r.Digest, r.Environment, r.RevokedBy, r.RevokedAt.UTC(), r.Reason)
	return err
}

func (s *SQLStore) GetRevocations(env string) ([]Revocation, error) {
	var rows *sql.Rows
	var err error
	if env == "" {
		rows, err = s.db.Query("SELECT id, digest, environment, revoked_by, revoked_at, COALESCE(reason, '') FROM revocations ORDER BY revoked_at ASC")
	} else {
		rows, err = s.db.Query("SELECT id, digest, environment, revoked_by, revoked_at, COALESCE(reason, '') FROM revocations WHERE environment = $1 ORDER BY revoked_at ASC", env)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.ID, &r.Digest, &r.Environment, &r.RevokedBy, &r.RevokedAt, &r.Reason); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (s *SQLStore) IsRevoked(digest, env string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM revocations WHERE digest = $1 AND (environment = '' OR environment = $2)`
	err := s.db.QueryRow(query, digest, env).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLStore) Quarantine(q Quarantine) error {
	if q.ID == "" {
		q.ID = newID("quar")
	}
	if q.QuarantinedAt.IsZero() {
		q.QuarantinedAt = time.Now().UTC()
	}
	query := `INSERT INTO quarantines (id, digest, environment, quarantined_by, quarantined_at, reason, incident_id) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.db.Exec(query, q.ID, q.Digest, q.Environment, q.QuarantinedBy, q.QuarantinedAt.UTC(), q.Reason, q.IncidentID)
	return err
}

func (s *SQLStore) GetQuarantines(env string) ([]Quarantine, error) {
	var rows *sql.Rows
	var err error
	if env == "" {
		rows, err = s.db.Query("SELECT id, digest, environment, quarantined_by, quarantined_at, COALESCE(reason, ''), COALESCE(incident_id, '') FROM quarantines ORDER BY quarantined_at ASC")
	} else {
		rows, err = s.db.Query("SELECT id, digest, environment, quarantined_by, quarantined_at, COALESCE(reason, ''), COALESCE(incident_id, '') FROM quarantines WHERE environment = '' OR environment = $1 ORDER BY quarantined_at ASC", env)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Quarantine
	for rows.Next() {
		var q Quarantine
		if err := rows.Scan(&q.ID, &q.Digest, &q.Environment, &q.QuarantinedBy, &q.QuarantinedAt, &q.Reason, &q.IncidentID); err != nil {
			return nil, err
		}
		list = append(list, q)
	}
	return list, rows.Err()
}

func (s *SQLStore) IsQuarantined(digest, env string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM quarantines WHERE digest = $1 AND (environment = '' OR environment = $2)`
	err := s.db.QueryRow(query, digest, env).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLStore) Unquarantine(id string) error {
	_, err := s.db.Exec("DELETE FROM quarantines WHERE id = $1 OR digest = $1", id)
	return err
}

func (s *SQLStore) Backup() ([]byte, error) {
	decs, err := s.GetDecisions()
	if err != nil {
		return nil, err
	}
	proms, err := s.GetPromotions("")
	if err != nil {
		return nil, err
	}
	revs, err := s.GetRevocations("")
	if err != nil {
		return nil, err
	}
	quars, err := s.GetQuarantines("")
	if err != nil {
		return nil, err
	}
	backup := BackupData{
		SchemaVersion: "1.0.0",
		ExportedAt:    time.Now().UTC(),
		Decisions:     decs,
		Promotions:    proms,
		Revocations:   revs,
		Quarantines:   quars,
	}
	return json.MarshalIndent(backup, "", "  ")
}

func (s *SQLStore) Restore(data []byte) error {
	var backup BackupData
	if err := json.Unmarshal(data, &backup); err != nil {
		return fmt.Errorf("unmarshal backup: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM decisions; DELETE FROM promotions; DELETE FROM revocations; DELETE FROM quarantines;"); err != nil {
		return err
	}
	for _, d := range backup.Decisions {
		b, _ := json.Marshal(d)
		if _, err := tx.Exec("INSERT INTO decisions (decision_id, schema_version, decision, subject_name, subject_version, subject_digest, environment, policy_name, policy_digest, evaluated_at, data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)", d.DecisionID, d.SchemaVersion, d.Decision, d.Subject.Name, d.Subject.Version, d.Subject.Digest, d.Environment, d.PolicyName, d.PolicyDigest, d.EvaluatedAt.UTC(), string(b)); err != nil {
			return err
		}
	}
	for _, p := range backup.Promotions {
		if _, err := tx.Exec("INSERT INTO promotions (id, decision_id, digest, environment, promoted_by, promoted_at, reason) VALUES ($1, $2, $3, $4, $5, $6, $7)", p.ID, p.DecisionID, p.Digest, p.Environment, p.PromotedBy, p.PromotedAt.UTC(), p.Reason); err != nil {
			return err
		}
	}
	for _, r := range backup.Revocations {
		if _, err := tx.Exec("INSERT INTO revocations (id, digest, environment, revoked_by, revoked_at, reason) VALUES ($1, $2, $3, $4, $5, $6)", r.ID, r.Digest, r.Environment, r.RevokedBy, r.RevokedAt.UTC(), r.Reason); err != nil {
			return err
		}
	}
	for _, q := range backup.Quarantines {
		if _, err := tx.Exec("INSERT INTO quarantines (id, digest, environment, quarantined_by, quarantined_at, reason, incident_id) VALUES ($1, $2, $3, $4, $5, $6, $7)", q.ID, q.Digest, q.Environment, q.QuarantinedBy, q.QuarantinedAt.UTC(), q.Reason, q.IncidentID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

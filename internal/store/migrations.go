package store

import (
	"database/sql"
	"fmt"
)

type Migration struct {
	Version int
	Name    string
	SQL     string
}

var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		SQL: `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id VARCHAR(128) PRIMARY KEY,
    schema_version VARCHAR(32) NOT NULL,
    decision VARCHAR(64) NOT NULL,
    subject_name VARCHAR(256) NOT NULL,
    subject_version VARCHAR(64) NOT NULL,
    subject_digest VARCHAR(128) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    policy_name VARCHAR(256) NOT NULL,
    policy_digest VARCHAR(128) NOT NULL,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS promotions (
    id VARCHAR(128) PRIMARY KEY,
    decision_id VARCHAR(128),
    digest VARCHAR(128) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    promoted_by VARCHAR(256) NOT NULL,
    promoted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS revocations (
    id VARCHAR(128) PRIMARY KEY,
    digest VARCHAR(128) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    revoked_by VARCHAR(256) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_decisions_subject_digest ON decisions(subject_digest);
CREATE INDEX IF NOT EXISTS idx_promotions_digest ON promotions(digest, environment);
CREATE INDEX IF NOT EXISTS idx_revocations_digest ON revocations(digest, environment);
`,
	},
}

func Migrate(db *sql.DB) error {
	for _, m := range migrations {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		var count int
		_ = tx.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = $1", m.Version).Scan(&count)
		if count > 0 {
			_ = tx.Rollback()
			continue
		}

		if _, err := tx.Exec(m.SQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Name, err)
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", m.Version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d failed: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

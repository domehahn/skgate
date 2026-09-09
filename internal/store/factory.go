package store

import (
	"database/sql"
	"fmt"
	"strings"
)

func NewStore(engine string, dataDir string, dsn string) (Store, error) {
	switch strings.ToLower(engine) {
	case "postgres", "postgresql", "sql":
		if dsn == "" {
			return nil, fmt.Errorf("storage engine %q requires a non-empty dsn", engine)
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("open database: %w", err)
		}
		return NewSQLStore(db)
	case "", "file", "ndjson":
		if dataDir == "" {
			dataDir = "./data"
		}
		return NewFileStore(dataDir)
	default:
		return nil, fmt.Errorf("unsupported storage engine %q (supported: file, postgres)", engine)
	}
}

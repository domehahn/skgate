package store

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"sync"
	"testing"
)

type mockDriver struct {
	mu            sync.Mutex
	applied       map[int]bool
	failAtVersion int
	execCount     int
}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	return &mockConn{d: d}, nil
}

type mockConn struct {
	d *mockDriver
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{c: c, query: query}, nil
}

func (c *mockConn) Close() error { return nil }

func (c *mockConn) Begin() (driver.Tx, error) {
	return &mockTx{}, nil
}

type mockTx struct{}

func (tx *mockTx) Commit() error   { return nil }
func (tx *mockTx) Rollback() error { return nil }

type mockStmt struct {
	c     *mockConn
	query string
}

func (s *mockStmt) Close() error { return nil }
func (s *mockStmt) NumInput() int { return -1 }

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	if s.c.d.failAtVersion > 0 {
		return nil, fmt.Errorf("simulated migration exec failure for version %d", s.c.d.failAtVersion)
	}
	s.c.d.execCount++
	return mockResult{}, nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()

	if len(args) > 0 {
		if ver, ok := args[0].(int64); ok {
			if s.c.d.failAtVersion > 0 && int(ver) == s.c.d.failAtVersion {
				return nil, fmt.Errorf("simulated migration query failure for version %d", ver)
			}
			count := int64(0)
			if s.c.d.applied[int(ver)] {
				count = 1
			}
			return &mockRows{columns: []string{"count"}, rows: [][]driver.Value{{count}}}, nil
		}
	}
	return &mockRows{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}}, nil
}

type mockResult struct{}

func (r mockResult) LastInsertId() (int64, error) { return 0, nil }
func (r mockResult) RowsAffected() (int64, error) { return 1, nil }

type mockRows struct {
	columns []string
	rows    [][]driver.Value
	pos     int
}

func (r *mockRows) Columns() []string { return r.columns }
func (r *mockRows) Close() error      { return nil }
func (r *mockRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.pos])
	r.pos++
	return nil
}

var (
	driverOnce sync.Once
	testDriver *mockDriver
)

func getTestDB(t *testing.T) (*sql.DB, *mockDriver) {
	driverOnce.Do(func() {
		testDriver = &mockDriver{applied: make(map[int]bool)}
		sql.Register("mock_migration_driver", testDriver)
	})
	testDriver.mu.Lock()
	testDriver.applied = make(map[int]bool)
	testDriver.failAtVersion = 0
	testDriver.execCount = 0
	testDriver.mu.Unlock()

	db, err := sql.Open("mock_migration_driver", "")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	return db, testDriver
}

func TestMigrationExecution(t *testing.T) {
	db, drv := getTestDB(t)
	defer db.Close()

	if err := Migrate(db); err != nil {
		t.Fatalf("expected Migrate to succeed, got %v", err)
	}

	drv.mu.Lock()
	if drv.execCount == 0 {
		t.Fatal("expected migration SQL execution calls")
	}
	drv.mu.Unlock()
}

func TestMigrationIdempotency(t *testing.T) {
	db, drv := getTestDB(t)
	defer db.Close()

	// Mark all migrations as applied
	drv.mu.Lock()
	for _, m := range migrations {
		drv.applied[m.Version] = true
	}
	drv.mu.Unlock()

	if err := Migrate(db); err != nil {
		t.Fatalf("expected Migrate to succeed on already applied migrations, got %v", err)
	}
}

func TestMigrationRollbackOnFailure(t *testing.T) {
	db, drv := getTestDB(t)
	defer db.Close()

	drv.mu.Lock()
	drv.failAtVersion = 1
	drv.mu.Unlock()

	err := Migrate(db)
	if err == nil {
		t.Fatal("expected Migrate to fail when version query fails")
	}
}

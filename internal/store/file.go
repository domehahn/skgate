package store

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/domehahn/skgate/internal/admission"
)

type FileStore struct {
	mu          sync.RWMutex
	dataDir     string
	decisions   string
	promotions  string
	revocations string
}

func NewFileStore(dataDir string) (*FileStore, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{
		dataDir:     dataDir,
		decisions:   filepath.Join(dataDir, "decisions.ndjson"),
		promotions:  filepath.Join(dataDir, "promotions.ndjson"),
		revocations: filepath.Join(dataDir, "revocations.ndjson"),
	}, nil
}

func (fs *FileStore) SaveDecision(d admission.Decision) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return appendNDJSON(fs.decisions, d)
}

func (fs *FileStore) GetDecisions() ([]admission.Decision, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return readNDJSON[admission.Decision](fs.decisions)
}

func (fs *FileStore) Promote(p Promotion) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if p.ID == "" {
		p.ID = newID("promo")
	}
	if p.PromotedAt.IsZero() {
		p.PromotedAt = time.Now().UTC()
	}
	return appendNDJSON(fs.promotions, p)
}

func (fs *FileStore) GetPromotions(env string) ([]Promotion, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	all, err := readNDJSON[Promotion](fs.promotions)
	if err != nil {
		return nil, err
	}
	if env == "" {
		return all, nil
	}
	var filtered []Promotion
	for _, item := range all {
		if item.Environment == env {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func (fs *FileStore) Revoke(r Revocation) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if r.ID == "" {
		r.ID = newID("rev")
	}
	if r.RevokedAt.IsZero() {
		r.RevokedAt = time.Now().UTC()
	}
	return appendNDJSON(fs.revocations, r)
}

func (fs *FileStore) GetRevocations(env string) ([]Revocation, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	all, err := readNDJSON[Revocation](fs.revocations)
	if err != nil {
		return nil, err
	}
	if env == "" {
		return all, nil
	}
	var filtered []Revocation
	for _, item := range all {
		if item.Environment == env {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func (fs *FileStore) IsRevoked(digest, env string) (bool, error) {
	revs, err := fs.GetRevocations(env)
	if err != nil {
		return false, err
	}
	for _, r := range revs {
		if r.Digest == digest && (r.Environment == "" || r.Environment == env) {
			return true, nil
		}
	}
	return false, nil
}

func (fs *FileStore) Backup() ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	decs, err := readNDJSON[admission.Decision](fs.decisions)
	if err != nil {
		return nil, fmt.Errorf("read decisions for backup: %w", err)
	}
	proms, err := readNDJSON[Promotion](fs.promotions)
	if err != nil {
		return nil, fmt.Errorf("read promotions for backup: %w", err)
	}
	revs, err := readNDJSON[Revocation](fs.revocations)
	if err != nil {
		return nil, fmt.Errorf("read revocations for backup: %w", err)
	}

	backup := BackupData{
		SchemaVersion: "1.0.0",
		ExportedAt:    time.Now().UTC(),
		Decisions:     decs,
		Promotions:    proms,
		Revocations:   revs,
	}
	return json.MarshalIndent(backup, "", "  ")
}

func (fs *FileStore) Restore(data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var backup BackupData
	if err := json.Unmarshal(data, &backup); err != nil {
		return fmt.Errorf("unmarshal backup data: %w", err)
	}

	_ = os.Remove(fs.decisions)
	_ = os.Remove(fs.promotions)
	_ = os.Remove(fs.revocations)

	for _, d := range backup.Decisions {
		if err := appendNDJSON(fs.decisions, d); err != nil {
			return err
		}
	}
	for _, p := range backup.Promotions {
		if err := appendNDJSON(fs.promotions, p); err != nil {
			return err
		}
	}
	for _, r := range backup.Revocations {
		if err := appendNDJSON(fs.revocations, r); err != nil {
			return err
		}
	}
	return nil
}

func appendNDJSON(path string, v any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func readNDJSON[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var items []T
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			return nil, fmt.Errorf("parse line in %s: %w", path, err)
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b[:]))
}

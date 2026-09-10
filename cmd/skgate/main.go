package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/domehahn/skgate/internal/admission"
	"github.com/domehahn/skgate/internal/api"
	"github.com/domehahn/skgate/internal/auth"
	"github.com/domehahn/skgate/internal/policy"
	"github.com/domehahn/skgate/internal/store"
)

var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println(Version)
		return nil
	case "policy":
		return runPolicy(args[1:])
	case "evaluate":
		return runEvaluate(args[1:])
	case "serve":
		return runServe(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "promote":
		return runPromote(args[1:])
	case "revoke":
		return runRevoke(args[1:])
	case "promotions":
		return runPromotions(args[1:])
	case "revocations":
		return runRevocations(args[1:])
	case "quarantine":
		return runQuarantine(args[1:])
	case "unquarantine":
		return runUnquarantine(args[1:])
	case "quarantines":
		return runQuarantines(args[1:])
	case "reassess":
		return runReassess(args[1:])
	case "affected":
		return runAffected(args[1:])
	case "inventory":
		return runInventory(args[1:])
	case "backup":
		return runBackup(args[1:])
	case "restore":
		return runRestore(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() error {
	fmt.Println("skgate - agent skill admission and governance plane\n\ncommands: version, policy validate, evaluate, serve, doctor, promote, revoke, promotions, revocations, quarantine, unquarantine, quarantines, reassess, affected, inventory, backup, restore")
	return nil
}

func runPolicy(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("usage: skgate policy validate --policy <file>")
	}
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	path := fs.String("policy", "", "policy JSON file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--policy is required")
	}
	p, err := policy.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("policy %q valid (schema %s)\n", p.Name, p.SchemaVersion)
	return nil
}

func runEvaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	pp := fs.String("policy", "", "policy JSON")
	in := fs.String("input", "", "evaluation request JSON")
	out := fs.String("output", "", "output file (default stdout)")
	dd := fs.String("data-dir", "./data", "data directory for file store")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN connection string for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pp == "" || *in == "" {
		return errors.New("--policy and --input are required")
	}
	p, err := policy.Load(*pp)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var req admission.EvaluationRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return err
	}

	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return fmt.Errorf("storage initialization failed: %w", err)
	}
	evaluator := admission.New(p)
	if st != nil {
		evaluator = evaluator.WithRevocations(st).WithQuarantines(st)
	}

	d := evaluator.Evaluate(req)
	if st != nil {
		_ = st.SaveDecision(d)
	}
	enc, _ := json.MarshalIndent(d, "", "  ")
	enc = append(enc, '\n')
	if *out != "" {
		return os.WriteFile(*out, enc, 0o600)
	}
	_, err = os.Stdout.Write(enc)
	return err
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	pp := fs.String("policy", "", "policy JSON")
	dd := fs.String("data-dir", "./data", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pp == "" {
		return errors.New("--policy is required")
	}
	if _, err := policy.Load(*pp); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if err := os.MkdirAll(*dd, 0o700); err != nil {
		return err
	}
	probe := filepath.Join(*dd, ".write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return err
	}
	_ = os.Remove(probe)
	fmt.Println("doctor: PASS")
	return nil
}

func runPromote(args []string) error {
	fs := flag.NewFlagSet("promote", flag.ContinueOnError)
	decisionID := fs.String("decision-id", "", "decision_id of prior ALLOW admission decision (required)")
	digest := fs.String("digest", "", "artifact digest (sha256:<hex>)")
	env := fs.String("env", "", "target environment")
	by := fs.String("by", "cli", "promoted by user/service")
	reason := fs.String("reason", "", "promotion reason")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *decisionID == "" || *digest == "" || *env == "" {
		return errors.New("--decision-id, --digest, and --env are required")
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	p := store.Promotion{DecisionID: *decisionID, Digest: *digest, Environment: *env, PromotedBy: *by, Reason: *reason}
	if err := st.Promote(p); err != nil {
		return err
	}
	fmt.Printf("promoted digest %s (decision %s) to environment %q\n", *digest, *decisionID, *env)
	return nil
}

func runRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	digest := fs.String("digest", "", "artifact digest (sha256:<hex>)")
	env := fs.String("env", "", "target environment (optional)")
	by := fs.String("by", "cli", "revoked by user/service")
	reason := fs.String("reason", "", "revocation reason")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *digest == "" {
		return errors.New("--digest is required")
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	r := store.Revocation{Digest: *digest, Environment: *env, RevokedBy: *by, Reason: *reason}
	if err := st.Revoke(r); err != nil {
		return err
	}
	fmt.Printf("revoked digest %s (environment %q)\n", *digest, *env)
	return nil
}

func runPromotions(args []string) error {
	fs := flag.NewFlagSet("promotions", flag.ContinueOnError)
	env := fs.String("env", "", "filter by environment")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	list, err := st.GetPromotions(*env)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(list, "", "  ")
	fmt.Println(string(enc))
	return nil
}

func runRevocations(args []string) error {
	fs := flag.NewFlagSet("revocations", flag.ContinueOnError)
	env := fs.String("env", "", "filter by environment")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	list, err := st.GetRevocations(*env)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(list, "", "  ")
	fmt.Println(string(enc))
	return nil
}

func runQuarantine(args []string) error {
	fs := flag.NewFlagSet("quarantine", flag.ContinueOnError)
	digest := fs.String("digest", "", "artifact digest (sha256:<hex>)")
	env := fs.String("env", "", "target environment (optional)")
	by := fs.String("by", "cli", "quarantined by user/service")
	reason := fs.String("reason", "", "quarantine reason")
	incidentID := fs.String("incident-id", "", "incident ID reference")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *digest == "" {
		return errors.New("--digest is required")
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	q := store.Quarantine{Digest: *digest, Environment: *env, QuarantinedBy: *by, Reason: *reason, IncidentID: *incidentID}
	if err := st.Quarantine(q); err != nil {
		return err
	}
	fmt.Printf("quarantined digest %s (environment %q)\n", *digest, *env)
	return nil
}

func runUnquarantine(args []string) error {
	fs := flag.NewFlagSet("unquarantine", flag.ContinueOnError)
	id := fs.String("id", "", "quarantine ID or digest")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("--id (quarantine ID or digest) is required")
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	if err := st.Unquarantine(*id); err != nil {
		return err
	}
	fmt.Printf("unquarantined %s\n", *id)
	return nil
}

func runQuarantines(args []string) error {
	fs := flag.NewFlagSet("quarantines", flag.ContinueOnError)
	env := fs.String("env", "", "filter by environment")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	list, err := st.GetQuarantines(*env)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(list, "", "  ")
	fmt.Println(string(enc))
	return nil
}

func runReassess(args []string) error {
	fs := flag.NewFlagSet("reassess", flag.ContinueOnError)
	pp := fs.String("policy", "", "policy JSON file (required)")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pp == "" {
		return errors.New("--policy is required")
	}
	p, err := policy.Load(*pp)
	if err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	decs, err := st.GetDecisions()
	if err != nil {
		return err
	}
	evaluator := admission.New(p).WithRevocations(st).WithQuarantines(st)
	var newDecisions []admission.Decision
	for _, oldDec := range decs {
		req := admission.EvaluationRequest{
			Subject:     oldDec.Subject,
			Environment: oldDec.Environment,
			Evidence: admission.Evidence{
				SchemaVersion:   "1.0.0",
				SubjectDigest:   oldDec.Subject.Digest,
				Provider:        p.Assurance.Provider,
				ProviderVersion: p.Assurance.MinimumVersion,
				CompletedAt:     time.Now().UTC(),
				Complete:        true,
				Passed:          true,
				Risk:            "low",
			},
		}
		newDec := evaluator.Evaluate(req)
		_ = st.SaveDecision(newDec)
		newDecisions = append(newDecisions, newDec)
	}
	enc, _ := json.MarshalIndent(newDecisions, "", "  ")
	fmt.Println(string(enc))
	return nil
}

func runAffected(args []string) error {
	fs := flag.NewFlagSet("affected", flag.ContinueOnError)
	env := fs.String("env", "", "filter by environment")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	revs, err := st.GetRevocations(*env)
	if err != nil {
		return err
	}
	quars, err := st.GetQuarantines(*env)
	if err != nil {
		return err
	}
	affectedSet := make(map[string]map[string]string)
	for _, r := range revs {
		if _, ok := affectedSet[r.Digest]; !ok {
			affectedSet[r.Digest] = make(map[string]string)
		}
		affectedSet[r.Digest]["revocation"] = r.Reason
	}
	for _, q := range quars {
		if _, ok := affectedSet[q.Digest]; !ok {
			affectedSet[q.Digest] = make(map[string]string)
		}
		affectedSet[q.Digest]["quarantine"] = q.Reason
	}
	enc, _ := json.MarshalIndent(affectedSet, "", "  ")
	fmt.Println(string(enc))
	return nil
}

func runInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	env := fs.String("env", "", "filter by environment")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	decs, err := st.GetDecisions()
	if err != nil {
		return err
	}
	type InventoryItem struct {
		Name        string    `json:"name"`
		Version     string    `json:"version"`
		Digest      string    `json:"digest"`
		Environment string    `json:"environment"`
		LastState   string    `json:"last_state"`
		EvaluatedAt time.Time `json:"evaluated_at"`
	}
	inventoryMap := make(map[string]InventoryItem)
	for _, d := range decs {
		if *env != "" && d.Environment != *env {
			continue
		}
		key := fmt.Sprintf("%s:%s", d.Subject.Digest, d.Environment)
		inventoryMap[key] = InventoryItem{
			Name:        d.Subject.Name,
			Version:     d.Subject.Version,
			Digest:      d.Subject.Digest,
			Environment: d.Environment,
			LastState:   d.Decision,
			EvaluatedAt: d.EvaluatedAt,
		}
	}
	var list []InventoryItem
	for _, item := range inventoryMap {
		list = append(list, item)
	}
	enc, _ := json.MarshalIndent(list, "", "  ")
	fmt.Println(string(enc))
	return nil
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dd := fs.String("data-dir", "./data", "data directory")
	out := fs.String("out", "", "output backup file path")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out backup file path is required")
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	b, err := st.Backup()
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o600)
}

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	dd := fs.String("data-dir", "./data", "data directory")
	in := fs.String("in", "", "input backup file path")
	storage := fs.String("storage", "file", "storage engine (file, postgres)")
	dsn := fs.String("dsn", "", "database DSN for postgres engine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("--in backup file path is required")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	return st.Restore(data)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	pp := fs.String("policy", "", "policy JSON")
	addr := fs.String("addr", ":8081", "listen address")
	dd := fs.String("data-dir", "./data", "data directory")
	storage := fs.String("storage", getEnvOrDefault("SKGATE_STORAGE_ENGINE", "file"), "storage engine (file, postgres)")
	dsn := fs.String("dsn", os.Getenv("SKGATE_STORAGE_DSN"), "database DSN for postgres engine")
	issuer := fs.String("oidc-issuer", os.Getenv("SKGATE_OIDC_ISSUER"), "expected OIDC JWT issuer (iss)")
	audience := fs.String("oidc-audience", os.Getenv("SKGATE_OIDC_AUDIENCE"), "expected OIDC JWT audience (aud)")
	prod := fs.Bool("production", false, "fail closed on missing auth")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pp == "" {
		return errors.New("--policy is required")
	}
	p, err := policy.Load(*pp)
	if err != nil {
		return err
	}
	st, err := store.NewStore(*storage, *dd, *dsn)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	srvAPI := api.New(admission.New(p).WithRevocations(st).WithQuarantines(st), st, os.Getenv("SKGATE_API_TOKEN"), *prod, logger)
	if *issuer != "" || *audience != "" {
		authenticator := auth.NewAuthenticator(os.Getenv("SKGATE_API_TOKEN"), nil).WithIssuer(*issuer).WithAudience(*audience)
		srvAPI.WithAuthenticator(authenticator)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           srvAPI.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("skgate listening", "addr", *addr, "production", *prod, "storage", *storage)
		errCh <- srv.ListenAndServe()
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		ctx2, c2 := contextWithTimeout(10 * time.Second)
		defer c2()
		return srv.Shutdown(ctx2)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Kept local to avoid leaking context setup throughout CLI code.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("expected run version to succeed, got %v", err)
	}
}

func TestCLIPolicyValidate(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")
	policyData := `{
  "schema_version": "1.0.0",
  "name": "prod-policy",
  "environments": ["production"],
  "assurance": {
    "provider": "skil",
    "minimum_version": "0.6.0"
  },
  "signatures": {
    "required": false,
    "trusted_identities": []
  },
  "capabilities": {
    "deny": ["arbitrary_shell"],
    "approval_required": []
  },
  "provenance": {
    "required": false
  },
  "risk": {
    "maximum": "medium"
  },
  "runtime": {
    "allowed_commands": ["git"],
    "timeout_seconds": 60,
    "max_output_bytes": 1048576
  }
}`
	if err := os.WriteFile(policyFile, []byte(policyData), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	if err := run([]string{"policy", "validate", "--policy", policyFile}); err != nil {
		t.Fatalf("expected policy validate to succeed, got %v", err)
	}
}

func TestCLIEvaluateQuarantineInventoryFlow(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")
	policyData := `{
  "schema_version": "1.0.0",
  "name": "prod-policy",
  "environments": ["production"],
  "assurance": {
    "provider": "skil",
    "minimum_version": "0.6.0"
  },
  "signatures": { "required": false, "trusted_identities": [] },
  "capabilities": { "deny": [], "approval_required": [] },
  "provenance": { "required": false },
  "risk": { "maximum": "medium" },
  "runtime": { "allowed_commands": ["git"], "timeout_seconds": 60, "max_output_bytes": 1048576 }
}`
	_ = os.WriteFile(policyFile, []byte(policyData), 0o600)

	reqFile := filepath.Join(dir, "request.json")
	reqData := `{
  "subject": {
    "name": "my-skill",
    "version": "1.0.0",
    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  },
  "environment": "production",
  "evidence": {
    "subject_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "provider": "skil",
    "provider_version": "0.6.0",
    "complete": true,
    "passed": true,
    "risk": "low"
  }
}`
	_ = os.WriteFile(reqFile, []byte(reqData), 0o600)

	dataDir := filepath.Join(dir, "data")

	// 1. Evaluate
	outFile := filepath.Join(dir, "decision.json")
	if err := run([]string{"evaluate", "--policy", policyFile, "--input", reqFile, "--output", outFile, "--data-dir", dataDir}); err != nil {
		t.Fatalf("expected evaluate to succeed, got %v", err)
	}

	// 2. Quarantine
	if err := run([]string{"quarantine", "--digest", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "--env", "production", "--data-dir", dataDir}); err != nil {
		t.Fatalf("expected quarantine to succeed, got %v", err)
	}

	// 3. Quarantines listing
	if err := run([]string{"quarantines", "--data-dir", dataDir}); err != nil {
		t.Fatalf("expected quarantines list to succeed, got %v", err)
	}

	// 4. Affected listing
	if err := run([]string{"affected", "--data-dir", dataDir}); err != nil {
		t.Fatalf("expected affected list to succeed, got %v", err)
	}

	// 5. Inventory listing
	if err := run([]string{"inventory", "--data-dir", dataDir}); err != nil {
		t.Fatalf("expected inventory list to succeed, got %v", err)
	}

	// 6. Unquarantine
	if err := run([]string{"unquarantine", "--id", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "--data-dir", dataDir}); err != nil {
		t.Fatalf("expected unquarantine to succeed, got %v", err)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	err := run([]string{"unknown-cmd"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

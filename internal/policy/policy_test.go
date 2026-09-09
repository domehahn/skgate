package policy

import "testing"

func TestValidateRejectsNoTrustedSigner(t *testing.T) {
	p := Policy{SchemaVersion: "1.0.0", Name: "p", Environments: []string{"prod"}, Assurance: AssurancePolicy{Provider: "skil", MinimumVersion: "0.6.0"}, Signatures: SignaturePolicy{Required: true}, Risk: RiskPolicy{Maximum: "low"}, Runtime: RuntimePolicy{TimeoutSeconds: 1, MaxOutputBytes: 1}}
	if p.Validate() == nil {
		t.Fatal("expected error")
	}
}

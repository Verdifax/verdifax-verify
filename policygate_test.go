package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func policyGateFixture(t *testing.T) (*artifacts.AuditBundle, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "policy-gate", "orchestrator-mock-allowed-run.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifacts.DecodeBundleStrict(raw)
	if err != nil {
		t.Fatalf("a record carrying policy_gate must decode strictly: %v", err)
	}
	doc, err := os.ReadFile(filepath.Join("testdata", "policy-gate", "api-test-allow-all-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b, doc
}

// An allowed run sealed by an orchestrator from October 2026 on names
// the policy the gate evaluated; the EPA section hash covers it, so the
// record verifies only with the values as sealed.
func TestPolicyGateIsReadAndCoveredByTheSectionHash(t *testing.T) {
	b, _ := policyGateFixture(t)
	r := verify(b)
	if !r.AllPassed {
		t.Fatalf("the fixture must verify: %+v", r.Artifacts)
	}
	pg := r.PolicyGate
	if !pg.Present || pg.PolicyID != "api-test-allow-all" || pg.PolicyVersion != "1.0.0" || pg.FiredRuleID != "allow-all" {
		t.Fatalf("policy gate not read: %+v", pg)
	}
	if b.EPA.PolicyHash == pg.PolicyHash {
		t.Fatal("epa.policy_hash is the fixed constant, not the gate's hash")
	}
	b.EPA.PolicyGate.PolicyVersion = "2.0.0"
	if verify(b).AllPassed {
		t.Fatal("editing the sealed policy version must fail verification")
	}
}

// --policy confirms that a document the reader holds is the hashed one:
// the right document matches, the same document with a changed version
// does not, and a different policy does not.
func TestPolicyDocumentCheck(t *testing.T) {
	b, doc := policyGateFixture(t)
	r := verify(b)
	applyPolicyDocument(r, doc)
	if !r.PolicyGate.DocumentMatch || !r.AllPassed || r.VerdictTier == "FAILED" {
		t.Fatalf("the sealed policy's own document must match: %+v", r.PolicyGate)
	}
	for name, edited := range map[string][]byte{
		"version changed": bytes.Replace(doc, []byte(`"policy_version": "1.0.0"`), []byte(`"policy_version": "1.0.1"`), 1),
		"rule changed":    bytes.Replace(doc, []byte(`"rule_id": "allow-all"`), []byte(`"rule_id": "allow-some"`), 1),
		"default changed": bytes.Replace(doc, []byte(`"default_effect": "deny"`), []byte(`"default_effect": "allow"`), 1),
		"not a policy":    []byte(`{"schema":"psl.v1"}`),
		"not even JSON":   []byte(`policy: allow all`),
	} {
		if bytes.Equal(edited, doc) {
			t.Fatalf("%s: the edit did not apply", name)
		}
		r := verify(b)
		applyPolicyDocument(r, edited)
		if r.PolicyGate.DocumentMatch || r.AllPassed || r.VerdictTier != "FAILED" {
			t.Errorf("%s: must fail, got %+v", name, r.PolicyGate)
		}
	}
	// A record with no policy gate cannot vouch for any document.
	raw, err := os.ReadFile(filepath.Join("testdata", "round18", "run-249-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	old, err := artifacts.DecodeBundleStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	r = verify(old)
	if r.PolicyGate.Present {
		t.Fatal("run 249 predates policy_gate")
	}
	applyPolicyDocument(r, doc)
	if r.PolicyGate.DocumentMatch || r.AllPassed {
		t.Fatal("--policy against a record without a policy gate must fail, not pass silently")
	}
}

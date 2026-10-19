package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Run 253 is the first public production record sealed with the policy
// gate and a live AI review (orchestrator 564f1d4, October 18, 2026).
// Its sealed policy is the production default policy, whose document is
// published in internal/policyhash/testdata, so --policy can be checked
// against a real record with a public document.
func TestR22Run253SealsThePolicyGateAndTheLiveReview(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round22", "run-253-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifacts.DecodeBundleStrict(raw)
	if err != nil {
		t.Fatalf("run 253 must decode strictly: %v", err)
	}
	r := verify(b)
	if r.VerdictTier != "VERIFIED_ANCHORED" || r.RecordCoverage != "complete_record_anchored" {
		t.Fatalf("run 253 must be complete record anchored: %s %s", r.VerdictTier, r.RecordCoverage)
	}
	pg := r.PolicyGate
	if !pg.Present || pg.PolicyID != "verdifax-default-baseline-permit" || pg.PolicyVersion != "1.0.0" ||
		pg.PolicyHash != "1a090975c0515a14296a0e68bb6840c5de4d76465369c50022e390b3da1e25d0" || pg.FiredRuleID != "baseline-permit" {
		t.Fatalf("policy gate not as sealed: %+v", pg)
	}
	if b.AivpT4.AdapterID != "live-claude-api" || b.AivpT4.Decision != "release" {
		t.Fatalf("run 253 must carry a released live review: %+v", b.AivpT4)
	}
	doc, err := os.ReadFile(filepath.Join("internal", "policyhash", "testdata", "production_baseline_permit.json"))
	if err != nil {
		t.Fatal(err)
	}
	applyPolicyDocument(r, doc)
	if !r.PolicyGate.DocumentMatch || !r.AllPassed {
		t.Fatalf("the published production policy must match run 253's sealed gate: %+v", r.PolicyGate)
	}
	b.EPA.PolicyGate.FiredRuleID = "allow-everything"
	if verify(b).AllPassed {
		t.Fatal("editing the sealed fired rule must fail verification")
	}
}

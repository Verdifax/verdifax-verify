package main

// Round ten of the external review, kept as permanent tests: a v1
// receipt leaf does not bind run_id, so the verifier must not present
// it as checked; receipt anchor v2 binds run_id; and a receipt that
// seals anchor_required fails when its anchor is removed or replaced.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// requireAnchor seals anchor_required into d's deny receipt and sets
// the document's run_id, as the v2 producer does.
func requireAnchor(t *testing.T, d *artifacts.ReceiptDocument, runID int64) {
	t.Helper()
	d.RunID = runID
	d.DenyReceipt.AnchorRequired = true
	d.DenyReceipt.Hash = ""
	if _, err := artifacts.BuildDenyReceiptHash(d.DenyReceipt); err != nil {
		t.Fatal(err)
	}
}

// anchorReceiptV2On logs d's receipt on l under the v2 recipe.
func anchorReceiptV2On(t *testing.T, l *testLog, d *artifacts.ReceiptDocument, loggedAfter time.Duration) {
	t.Helper()
	r := d.DenyReceipt
	clock, err := time.Parse(time.RFC3339Nano, r.DenyClock)
	if err != nil {
		t.Fatal(err)
	}
	l.integratedTime = clock.Add(loggedAfter).Unix()
	e := l.entry(t, strings.Repeat("0", 64),
		artifacts.ComputeReceiptLeafHashV2("deny_receipt", r.EnvelopeID, r.Hash, d.RunID))
	d.ReceiptAnchor = &artifacts.ReceiptAnchor{
		Kind: artifacts.ReceiptAnchorKindV2, ReceiptKind: "deny_receipt", ReceiptHash: r.Hash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex,
		LogIndex: e.LogIndex, TreeSize: e.TreeSize, RootHashHex: e.RootHashHex,
		InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime,
		EntryBody: e.EntryBody,
	}
}

// The reviewer's finding: run 241's run_id can be changed and the v1
// receipt still verifies, so the report must say run_id is unchecked.
func TestR10V1ReceiptRunIDIsReportedUnchecked(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run241-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	d.RunID = 999
	r := mustReceiptTier(t, "run 241 relabelled as run 999", "VERIFIED_ANCHORED", d)
	if r.RunIDBound {
		t.Fatal("a v1 receipt anchor does not bind run_id; the report must not say it does")
	}
}

func TestR10V2ReceiptBindsRunID(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	d := loadReceiptDoc(t)
	requireAnchor(t, d, 4242)
	anchorReceiptV2On(t, l, d, 2*time.Second)
	r := mustReceiptTier(t, "v2 receipt", "VERIFIED_ANCHORED", d)
	if !r.RunIDBound || !r.AnchorRequired {
		t.Fatalf("a verified v2 receipt binds run_id and reports anchor_required: %+v", r)
	}
	d.RunID = 4243
	mustReceiptTier(t, "v2 receipt relabelled to another run", "FAILED", d)
}

func TestR10AnchorRequiredReceiptAttacksFail(t *testing.T) {
	cases := map[string]func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument){
		"anchor deleted": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.ReceiptAnchor = nil
		},
		"anchor deleted, field edited, hash recomputed": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.ReceiptAnchor = nil
			d.DenyReceipt.FiredRuleID = "baseline-permit"
			d.DenyReceipt.Hash = ""
			_, _ = artifacts.BuildDenyReceiptHash(d.DenyReceipt)
		},
		"replaced by a v1 anchor": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			anchorReceiptOn(t, l, d, 2*time.Second)
		},
		"anchor moved off the public log": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.ReceiptAnchor.Backend = "mock"
		},
		"run_id changed": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.RunID++
		},
	}
	for name, attack := range cases {
		t.Run(name, func(t *testing.T) {
			l := fixedTestLog(t)
			l.install(t)
			d := loadReceiptDoc(t)
			requireAnchor(t, d, 4242)
			anchorReceiptV2On(t, l, d, 2*time.Second)
			attack(t, l, d)
			r := mustReceiptTier(t, name, "FAILED", d)
			if !receiptExitShouldFail(r, true) {
				t.Fatal("a failed receipt fails even with --allow-unanchored")
			}
		})
	}
}

// The stated limit: deleting the anchor AND rewriting the receipt
// without anchor_required, hash recomputed, leaves nothing anchored to
// contradict it. It is self-consistent only and fails by default, but
// it is not identified as tampered.
func TestR10RewrittenToUnrequiredIsSelfConsistentOnly(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	d := loadReceiptDoc(t)
	requireAnchor(t, d, 4242)
	anchorReceiptV2On(t, l, d, 2*time.Second)
	d.ReceiptAnchor = nil
	d.DenyReceipt.AnchorRequired = false
	d.DenyReceipt.Hash = ""
	if _, err := artifacts.BuildDenyReceiptHash(d.DenyReceipt); err != nil {
		t.Fatal(err)
	}
	r := mustReceiptTier(t, "rewritten without anchor_required", "SELF_CONSISTENT_NOT_ANCHORED", d)
	if !receiptExitShouldFail(r, false) {
		t.Fatal("an unanchored receipt fails by default")
	}
}

// anchor_required leaves every existing receipt hash unchanged.
func TestR10AnchorRequiredAbsentKeepsOldHashes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run241-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "anchor_required") {
		t.Fatal("run 241 predates anchor_required")
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hashErr := artifacts.VerifyDenyReceiptHash(d.DenyReceipt); hashErr != nil {
		t.Fatalf("run 241's hash must still recompute: %v", hashErr)
	}
}

// The v2 leaf recipe, frozen: identical vector in the orchestrator.
func TestR10ReceiptLeafV2Vector(t *testing.T) {
	got := artifacts.ComputeReceiptLeafHashV2("deny_receipt", "env-90be9af2753ff202",
		"bf176dddad8587ccf2955accbc4cf9cbcef84bbf8c50492077e50c4f7b4d4256", 241)
	if got != "fdc0e06c5f59ef0fbd5d8ef61d27e4805f9f7d546e9c1f081b5896e4738b871c" {
		t.Fatalf("v2 receipt leaf changed: %s", got)
	}
}

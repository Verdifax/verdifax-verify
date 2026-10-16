package main

// Round nine of the external review, kept as permanent tests: receipts
// are checked by the public verifier and anchored on the public log,
// and numbers must be written in their canonical form.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func loadReceiptDoc(t *testing.T) *artifacts.ReceiptDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-orchestrator-mock.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatalf("the producer's receipt document must decode strictly: %v", err)
	}
	return d
}

// anchorReceiptOn logs d's receipt on l, loggedAfter past its clock.
func anchorReceiptOn(t *testing.T, l *testLog, d *artifacts.ReceiptDocument, loggedAfter time.Duration) {
	t.Helper()
	r := d.DenyReceipt
	clock, err := time.Parse(time.RFC3339Nano, r.DenyClock)
	if err != nil {
		t.Fatal(err)
	}
	l.integratedTime = clock.Add(loggedAfter).Unix()
	e := l.entry(t, strings.Repeat("0", 64), artifacts.ComputeReceiptLeafHash("deny_receipt", r.EnvelopeID, r.Hash))
	d.ReceiptAnchor = &artifacts.ReceiptAnchor{
		Kind: artifacts.ReceiptAnchorKind, ReceiptKind: "deny_receipt", ReceiptHash: r.Hash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex,
		LogIndex: e.LogIndex, TreeSize: e.TreeSize, RootHashHex: e.RootHashHex,
		InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime,
		EntryBody: e.EntryBody,
	}
}

func mustReceiptTier(t *testing.T, what, tier string, d *artifacts.ReceiptDocument) *ReceiptReport {
	t.Helper()
	r := verifyReceiptDocument(d)
	if r.VerdictTier != tier {
		t.Fatalf("%s: tier %s, want %s (%s)", what, r.VerdictTier, tier, r.Reason)
	}
	return r
}

// The producer's receipt, anchored only on its in-memory mock ledger,
// is self-consistent but not anchored: it fails without the flag.
func TestR9ProducerReceiptOnMockLedgerIsNotAnchored(t *testing.T) {
	r := mustReceiptTier(t, "mock-anchored receipt", "SELF_CONSISTENT_NOT_ANCHORED", loadReceiptDoc(t))
	if !receiptExitShouldFail(r, false) || receiptExitShouldFail(r, true) {
		t.Fatal("an unanchored receipt fails unless --allow-unanchored is passed")
	}
}

func TestR9AnchoredReceiptVerifies(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	d := loadReceiptDoc(t)
	anchorReceiptOn(t, l, d, 2*time.Second)
	r := mustReceiptTier(t, "anchored receipt", "VERIFIED_ANCHORED", d)
	if receiptExitShouldFail(r, false) || r.Summary["fired_rule_id"] != d.DenyReceipt.FiredRuleID {
		t.Fatalf("anchored receipt must pass and report its values: %+v", r)
	}
}

func TestR9ReceiptAttacksFail(t *testing.T) {
	cases := map[string]func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument){
		"field edited, hash not recomputed": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.DenyReceipt.FiredRuleID = "baseline-permit"
		},
		"field edited, hash recomputed, original anchor kept": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.DenyReceipt.FiredRuleID = "some-other-rule"
			h, _ := artifacts.BuildDenyReceiptHash(d.DenyReceipt)
			d.DenyReceipt.Hash = h
		},
		"field edited, re-logged under another key": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.DenyReceipt.FiredRuleID = "some-other-rule"
			h, _ := artifacts.BuildDenyReceiptHash(d.DenyReceipt)
			d.DenyReceipt.Hash = h
			l.signer = otherSigner(t)
			anchorReceiptOn(t, l, d, 2*time.Second)
		},
		"re-logged by the pinned key a day later": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			anchorReceiptOn(t, l, d, 24*time.Hour)
		},
		"anchor names a different receipt hash": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.ReceiptAnchor.ReceiptHash = strings.Repeat("a", 64)
		},
		"anchor names a different receipt kind": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.ReceiptAnchor.ReceiptKind = "ccv_halt_receipt"
		},
		"signed timestamp edited time": func(t *testing.T, l *testLog, d *artifacts.ReceiptDocument) {
			d.ReceiptAnchor.IntegratedTime--
		},
	}
	for name, attack := range cases {
		t.Run(name, func(t *testing.T) {
			l := fixedTestLog(t)
			l.install(t)
			d := loadReceiptDoc(t)
			anchorReceiptOn(t, l, d, 2*time.Second)
			attack(t, l, d)
			r := mustReceiptTier(t, name, "FAILED", d)
			if !receiptExitShouldFail(r, true) {
				t.Fatal("a failed receipt fails even with --allow-unanchored")
			}
		})
	}
}

// Stripping the anchor downgrades to not anchored, which still fails
// by default and never reads as verified.
func TestR9StrippedReceiptAnchorIsNotVerified(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	d := loadReceiptDoc(t)
	anchorReceiptOn(t, l, d, 2*time.Second)
	d.ReceiptAnchor = nil
	r := mustReceiptTier(t, "stripped receipt", "SELF_CONSISTENT_NOT_ANCHORED", d)
	if !receiptExitShouldFail(r, false) {
		t.Fatal("a stripped receipt must fail by default")
	}
}

func TestR9ReceiptDocumentDecodesStrictly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-orchestrator-mock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !isReceiptDocument(raw) {
		t.Fatal("the producer's receipt document must route to receipt verification")
	}
	for name, repl := range map[string][2]string{
		"case-variant duplicate": {`"fired_rule_id": "mcd-llm-001"`, `"fired_rule_id": "baseline-permit", "FIRED_RULE_ID": "mcd-llm-001"`},
		"unmodeled key":          {`"fired_rule_id": "mcd-llm-001"`, `"fired_rule_id": "mcd-llm-001", "note": "x"`},
		"two receipts":           {`"ok": true`, `"ok": true, "ccv_halt_receipt": {}`},
	} {
		if !bytes.Contains(raw, []byte(repl[0])) {
			t.Fatalf("fixture shape changed for %s", name)
		}
		edited := bytes.Replace(raw, []byte(repl[0]), []byte(repl[1]), 1)
		d, err := artifacts.DecodeReceiptStrict(edited)
		if name == "two receipts" {
			if err == nil && verifyReceiptDocument(d).VerdictTier != "FAILED" {
				t.Fatal("a document with two receipts must fail")
			}
			continue
		}
		if !errors.Is(err, artifacts.ErrNotStrictJSON) {
			t.Fatalf("%s must be refused by strict decoding, got %v", name, err)
		}
	}
}

// Numbers must be written in their canonical form.
func TestR9NonCanonicalNumbersAreRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round8", "run-239-intact.json"))
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	_ = json.Unmarshal(raw, &probe)
	old := []byte(`"slsa_level":0`)
	if !bytes.Contains(raw, old) {
		t.Fatal("fixture shape changed")
	}
	for _, spelling := range []string{"0.0", "-0", "0e0", "00", "0.00000000000000000001"} {
		edited := bytes.Replace(raw, old, []byte(`"slsa_level":`+spelling), 1)
		if _, err := artifacts.DecodeBundleStrict(edited); !errors.Is(err, artifacts.ErrNotStrictJSON) {
			t.Errorf("slsa_level written %s must be refused, got %v", spelling, err)
		}
	}
	if _, err := artifacts.DecodeBundleStrict(raw); err != nil {
		t.Fatalf("the genuine record must decode: %v", err)
	}
}

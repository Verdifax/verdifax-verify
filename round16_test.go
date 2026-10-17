package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Run 245 is the refused first row of the production batch sent
// 2026-10-17 after records began sealing keyed origin hashes; its
// allowed second row, run 246, is published. The receipt verifies
// against the real pinned key with its run number bound.
func TestR16ProductionBatchReceiptRun245(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run245-production-batch.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatalf("the run 245 receipt document must decode strictly: %v", err)
	}
	r := mustReceiptTier(t, "run 245 batch receipt", "VERIFIED_ANCHORED", d)
	if !r.RunIDBound || !r.AnchorRequired || r.RunID != 245 {
		t.Fatalf("run 245 must verify with its run number bound and anchor_required: %+v", r)
	}
}

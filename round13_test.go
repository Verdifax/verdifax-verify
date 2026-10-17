package main

// Round twelve of the external review, kept as permanent tests: every
// receipt the Verdifax API has issued since run 241 carries a
// public-log anchor, so a receipt dated from then on without one fails
// unless the person checking says it came from a self-hosted
// deployment.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// run241Variant returns run 241's receipt with clock as its deny_clock
// and its hash recomputed; strip deletes the anchor.
func run241Variant(t *testing.T, clock string, strip bool) *artifacts.ReceiptDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run241-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strip {
		d.ReceiptAnchor = nil
	}
	if clock != d.DenyReceipt.DenyClock {
		d.DenyReceipt.DenyClock = clock
		d.DenyReceipt.Hash = ""
		if _, err := artifacts.BuildDenyReceiptHash(d.DenyReceipt); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestR12StrippedRun241Fails(t *testing.T) {
	d := run241Variant(t, "2026-10-16T23:11:17.94873898Z", true)
	r := mustReceiptTier(t, "run 241 with its anchor deleted", "FAILED", d)
	if !receiptExitShouldFail(r, true) {
		t.Fatal("it fails even with --allow-unanchored")
	}
	// The same instant written with an offset is the same instant.
	offset := run241Variant(t, "2026-10-16T19:11:17.94873898-04:00", true)
	mustReceiptTier(t, "run 241 stripped, clock written at -04:00", "FAILED", offset)
}

func TestR12AnchorOffThePublicLogFailsAfterRun241(t *testing.T) {
	d := run241Variant(t, "2026-10-16T23:11:17.94873898Z", false)
	d.ReceiptAnchor.Backend = "mock"
	mustReceiptTier(t, "run 241 with its anchor moved off the log", "FAILED", d)
}

// The remaining limit: backdated before run 241, a stripped receipt is
// self-consistent only and fails by default.
func TestR12BackdatedBeforeRun241IsSelfConsistentOnly(t *testing.T) {
	d := run241Variant(t, "2026-10-16T23:11:17.94873897Z", true)
	r := mustReceiptTier(t, "stripped receipt backdated before run 241", "SELF_CONSISTENT_NOT_ANCHORED", d)
	if !receiptExitShouldFail(r, false) {
		t.Fatal("an unanchored receipt fails by default")
	}
}

func TestR12SelfHostedReceiptIsExemptFromBothCutovers(t *testing.T) {
	d := run241Variant(t, "2026-10-17T12:00:00Z", true)
	r := verifyReceiptDocumentWith(d, receiptOptions{selfHosted: true})
	if r.VerdictTier != "SELF_CONSISTENT_NOT_ANCHORED" {
		t.Fatalf("self-hosted unanchored receipt: %s (%s)", r.VerdictTier, r.Reason)
	}
}

// Round fourteen: a clock written with an offset is printed with its
// UTC instant, so the failure does not read as a contradiction.
func TestR13OffsetClockIsPrintedWithItsUTCInstant(t *testing.T) {
	d := run241Variant(t, "2026-10-16T19:11:17.94873898-04:00", true)
	r := mustReceiptTier(t, "run 241 stripped, clock at -04:00", "FAILED", d)
	if !strings.Contains(r.Reason, "(2026-10-16T23:11:17.94873898Z)") {
		t.Fatalf("the reason must show the UTC instant: %s", r.Reason)
	}
	if datedUTC("2026-10-16T23:11:17.94873898Z") != "2026-10-16T23:11:17.94873898Z" {
		t.Fatal("a UTC clock is printed once")
	}
}

// Run 243 is the refused first row of a production batch (2026-10-17),
// anchored when the row was decided, before the batch's second row ran.
// It verifies against the real pinned key with its run number bound.
func TestR14ProductionBatchReceiptRun243(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run243-production-batch.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatalf("the run 243 receipt document must decode strictly: %v", err)
	}
	r := mustReceiptTier(t, "run 243 batch receipt", "VERIFIED_ANCHORED", d)
	if !r.RunIDBound || !r.AnchorRequired || r.RunID != 243 {
		t.Fatalf("run 243 must verify with its run number bound and anchor_required: %+v", r)
	}
}

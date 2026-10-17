package main

// Round eleven of the external review, kept as permanent tests: every
// receipt the Verdifax API has issued since run 242 seals
// anchor_required, so a receipt dated from then on without it fails
// unless the person checking says it came from a self-hosted
// deployment.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// run242Stripped returns run 242's receipt with its anchor deleted and
// anchor_required removed, the hash recomputed: the stated limit before
// this release, given clock as its deny_clock.
func run242Stripped(t *testing.T, clock string) *artifacts.ReceiptDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run242-production-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	d.ReceiptAnchor = nil
	d.DenyReceipt.AnchorRequired = false
	d.DenyReceipt.DenyClock = clock
	d.DenyReceipt.Hash = ""
	if _, err := artifacts.BuildDenyReceiptHash(d.DenyReceipt); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestR11StrippedReceiptAfterCutoverFails(t *testing.T) {
	d := run242Stripped(t, "2026-10-16T23:48:35.104252967Z")
	r := mustReceiptTier(t, "run 242 stripped of anchor and anchor_required", "FAILED", d)
	if !receiptExitShouldFail(r, true) {
		t.Fatal("it fails even with --allow-unanchored")
	}
	later := run242Stripped(t, "2027-01-01T00:00:00Z")
	mustReceiptTier(t, "stripped receipt dated later", "FAILED", later)
}

// The person checking can exempt a receipt they know came from a test
// or self-hosted deployment; it is then self-consistent only.
func TestR11SelfHostedReceiptIsExempt(t *testing.T) {
	d := run242Stripped(t, "2026-10-17T12:00:00Z")
	r := verifyReceiptDocumentWith(d, receiptOptions{selfHosted: true})
	if r.VerdictTier != "SELF_CONSISTENT_NOT_ANCHORED" {
		t.Fatalf("self-hosted receipt without anchor_required: %s (%s)", r.VerdictTier, r.Reason)
	}
}

// The flag exempts only the cutover rule: a receipt that seals
// anchor_required still fails without its anchor.
func TestR11SelfHostedDoesNotExcuseAMissingRequiredAnchor(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run242-production-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := artifacts.DecodeReceiptStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	d.ReceiptAnchor = nil
	if r := verifyReceiptDocumentWith(d, receiptOptions{selfHosted: true}); r.VerdictTier != "FAILED" {
		t.Fatalf("required anchor deleted, self-hosted flag: %s", r.VerdictTier)
	}
}

// The remaining limit: backdated before the cutover, a stripped receipt
// is self-consistent only, and its sealed date has had to change.
func TestR11BackdatedStrippedReceiptIsSelfConsistentOnly(t *testing.T) {
	d := run242Stripped(t, "2026-10-16T23:48:35.104252966Z")
	r := mustReceiptTier(t, "stripped receipt backdated one nanosecond", "SELF_CONSISTENT_NOT_ANCHORED", d)
	if !receiptExitShouldFail(r, false) {
		t.Fatal("an unanchored receipt fails by default")
	}
}

// Every real receipt keeps its verdict under the cutover rule.
func TestR11RealReceiptsKeepTheirVerdicts(t *testing.T) {
	for name, tier := range map[string]string{
		"deny-receipt-run241-production.json":    "VERIFIED_ANCHORED",
		"deny-receipt-run242-production-v2.json": "VERIFIED_ANCHORED",
		"deny-receipt-orchestrator-mock.json":    "SELF_CONSISTENT_NOT_ANCHORED",
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", "round10", name))
		if err != nil {
			t.Fatal(err)
		}
		d, err := artifacts.DecodeReceiptStrict(raw)
		if err != nil {
			t.Fatal(err)
		}
		mustReceiptTier(t, name, tier, d)
	}
}

func TestR11UnparseableClockFails(t *testing.T) {
	d := run242Stripped(t, "yesterday")
	mustReceiptTier(t, "receipt with an unparseable clock", "FAILED", d)
}

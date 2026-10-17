package main

// Receipt verification (v0.13.0), the answer to round nine of the
// external review.
//
// A refused or halted run produces a sealed receipt instead of an audit
// bundle. Its hash recomputes from its own fields, which shows the
// receipt is self-consistent, not who issued it or when; anyone can
// rewrite a receipt and recompute its hash. Earlier releases could not
// check receipts at all: the only checker lived in the private
// orchestrator. This tool now reads the receipt document the Verdifax
// API serves and checks:
//
//   - the receipt's hash, recomputed from its own fields;
//   - its receipt_anchor: the leaf rebuilt from the receipt's kind,
//     envelope_id and hash, the Rekor inclusion proof, signed
//     checkpoint, entry body and signed entry timestamp, the pinned
//     Verdifax log-signing key within its period, and the v1 window
//     (the entry logged within 600 seconds after the receipt's own
//     clock), so a receipt cannot be rewritten later and keep its date.
//
// A receipt without an anchor, or whose anchor is not on the public
// log, is SELF-CONSISTENT ONLY, NOT ANCHORED: it fails unless
// --allow-unanchored is passed, exactly as an unanchored bundle does.
//
// Receipt anchor v2 (v0.14.0, round ten of the external review). A v1
// leaf does not bind the document's run_id, so the run number of a v1
// receipt is printed as taken from the document, not checked. A v2
// leaf also binds run_id, and a receipt anchored under v2 seals
// anchor_required in its own hash: such a receipt with its anchor
// deleted, replaced by a v1 or off-log anchor, FAILS. The document's
// "ok" field is the API's response flag; it is not checked and is not
// reported.
//
// The anchor_required cutover (v0.14.1, round eleven of the external
// review). Every receipt the Verdifax API has issued since run 242
// (receiptAnchorRequiredSince) seals anchor_required. A receipt dated at
// or after that instant without the field was rewritten, or came from a
// deployment that does not anchor receipts on the public log, so it
// FAILS unless the person checking it passes --self-hosted-receipt. The
// clock is inside the receipt's hash, so evading the rule means
// backdating the receipt, which changes its sealed date.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// ReceiptReport is the --json output for a receipt document.
type ReceiptReport struct {
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version"`
	ReceiptKind  string `json:"receipt_kind"`
	RunID        int64  `json:"run_id"`
	EnvelopeID   string `json:"envelope_id"`
	ReceiptClock string `json:"receipt_clock"`
	ReceiptHash  string `json:"receipt_hash"`
	HashOK       bool   `json:"receipt_hash_ok"`
	// RunIDBound is true only when a verified v2 anchor binds run_id;
	// otherwise run_id is the document's claim, not checked.
	RunIDBound bool `json:"run_id_bound"`
	// AnchorRequired is the receipt's sealed anchor_required value.
	AnchorRequired bool `json:"anchor_required"`
	// Summary is the receipt's decision-bearing fields as checked.
	Summary          map[string]string `json:"record_values"`
	AnchorPresent    bool              `json:"anchor_present"`
	Anchored         bool              `json:"anchored"`
	AnchorLogEntry   string            `json:"anchor_log_entry_id,omitempty"`
	SignerName       string            `json:"signer_name,omitempty"`
	SignerFP         string            `json:"signer_fingerprint,omitempty"`
	AnchoredAt       string            `json:"anchored_at,omitempty"`
	GapSeconds       *int64            `json:"anchor_gap_seconds,omitempty"`
	WindowSeconds    int64             `json:"anchoring_window_seconds,omitempty"`
	AllPassed        bool              `json:"all_passed"`
	VerdictTier      string            `json:"verdict_tier"`
	Reason           string            `json:"reason,omitempty"`
	StaleEntryNumber bool              `json:"stale_entry_number,omitempty"`
}

// receiptFacts is the kind-independent view of one receipt.
type receiptFacts struct {
	kind, envelopeID, clock, hash string
	hashErr                       error
	summary                       map[string]string
}

func factsOf(d *artifacts.ReceiptDocument) ([]receiptFacts, error) {
	var out []receiptFacts
	if r := d.DenyReceipt; r != nil {
		out = append(out, receiptFacts{"deny_receipt", r.EnvelopeID, r.DenyClock, r.Hash,
			artifacts.VerifyDenyReceiptHash(r), map[string]string{
				"fired_rule_id": r.FiredRuleID, "decision_reason_code": r.DecisionReasonCode,
				"policy_hash": r.PolicyHash}})
	}
	if r := d.CCVHaltReceipt; r != nil {
		out = append(out, receiptFacts{"ccv_halt_receipt", r.EnvelopeID, r.HaltClock, r.Hash,
			artifacts.VerifyCCVHaltReceiptHash(r), map[string]string{
				"halt_reason_code": r.HaltReasonCode, "budget_hash": r.BudgetHash}})
	}
	if r := d.MACCHaltReceipt; r != nil {
		out = append(out, receiptFacts{"macc_halt_receipt", r.EnvelopeID, r.HaltClock, r.Hash,
			artifacts.VerifyMACCHaltReceiptHash(r), map[string]string{
				"halt_reason_code": r.HaltReasonCode, "budget_hash": r.BudgetHash}})
	}
	if r := d.AivpT4HaltReceipt; r != nil {
		out = append(out, receiptFacts{"aivp_t4_halt_receipt", r.EnvelopeID, r.HaltClock, r.Hash,
			artifacts.VerifyAivpT4HaltReceiptHash(r), map[string]string{
				"halt_reason_code": r.HaltReasonCode, "pia_hash": r.PiaHash, "ai_output_hash": r.AiOutputHash}})
	}
	if r := d.AttestationGapReceipt; r != nil {
		out = append(out, receiptFacts{"attestation_gap_receipt", r.EnvelopeID, r.GapClock, r.Hash,
			artifacts.VerifyAttestationGapReceiptHash(r), map[string]string{
				"decision_reason_code": r.DecisionReasonCode, "policy_hash": r.PolicyHash}})
	}
	if len(out) != 1 {
		return nil, fmt.Errorf("a receipt document must carry exactly one receipt, this one carries %d", len(out))
	}
	return out, nil
}

// receiptAnchorRequiredSince is the deny_clock of run 242, the first
// receipt the Verdifax API issued under receipt anchor v2; every
// receipt it has issued since seals anchor_required.
const receiptAnchorRequiredSince = "2026-10-16T23:48:35.104252967Z"

// receiptOptions are the receipt checks the person verifying chooses.
type receiptOptions struct {
	// selfHosted exempts a receipt from the anchor_required cutover: it
	// was issued by a test or self-hosted deployment that does not
	// anchor receipts on the public log, not by the Verdifax API.
	selfHosted bool
}

// verifyReceiptDocument checks one served receipt document as issued by
// the Verdifax API.
func verifyReceiptDocument(d *artifacts.ReceiptDocument) *ReceiptReport {
	return verifyReceiptDocumentWith(d, receiptOptions{})
}

// verifyReceiptDocumentWith checks one receipt document under opts.
func verifyReceiptDocumentWith(d *artifacts.ReceiptDocument, opts receiptOptions) *ReceiptReport {
	rep := &ReceiptReport{Tool: "verdifax-verify", ToolVersion: Version, RunID: d.RunID, VerdictTier: "FAILED"}
	fail := func(format string, args ...any) *ReceiptReport {
		rep.AllPassed = false
		rep.VerdictTier = "FAILED"
		rep.Reason = fmt.Sprintf(format, args...)
		return rep
	}
	all, shapeErr := factsOf(d)
	if shapeErr != nil {
		return fail("%v", shapeErr)
	}
	f := all[0]
	rep.ReceiptKind, rep.EnvelopeID, rep.ReceiptClock, rep.ReceiptHash, rep.Summary =
		f.kind, f.envelopeID, f.clock, f.hash, f.summary
	if f.hashErr != nil {
		return fail("the receipt's hash does not recompute from its own fields: %v", f.hashErr)
	}
	rep.HashOK = true
	required := anchorRequiredOf(d)
	rep.AnchorRequired = required
	if !required && !opts.selfHosted {
		if afterCutover, cutoverErr := issuedAfterAnchorRequired(f.clock); cutoverErr != nil {
			return fail("the receipt's clock %q is not an RFC 3339 time", safePrefix(f.clock))
		} else if afterCutover {
			return fail("this receipt is dated %s, at or after %s, since when every receipt the Verdifax API "+
				"issues seals anchor_required, and it does not: it was rewritten, or it was issued by a "+
				"deployment that does not anchor receipts (pass --self-hosted-receipt only if you know it was)",
				f.clock, receiptAnchorRequiredSince)
		}
	}

	a := d.ReceiptAnchor
	if a == nil {
		if required {
			return fail("this receipt seals anchor_required, so it must carry a public-log receipt_anchor, " +
				"and it carries none: the entry was removed, or anchoring failed when the receipt was issued")
		}
		rep.AllPassed, rep.VerdictTier = true, "SELF_CONSISTENT_NOT_ANCHORED"
		rep.Reason = "the receipt carries no receipt_anchor, so nothing shows who issued it or when"
		return rep
	}
	rep.AnchorPresent = true
	rep.AnchorLogEntry = a.LogEntryID
	v2 := a.Kind == artifacts.ReceiptAnchorKindV2
	switch {
	case a.Kind != artifacts.ReceiptAnchorKind && !v2:
		return fail("receipt_anchor is kind %q; this verifier knows %q and %q", a.Kind,
			artifacts.ReceiptAnchorKind, artifacts.ReceiptAnchorKindV2)
	case required && !v2:
		return fail("this receipt seals anchor_required, which only a %s anchor satisfies; it carries %q",
			artifacts.ReceiptAnchorKindV2, a.Kind)
	case a.ReceiptKind != f.kind:
		return fail("receipt_anchor names a %s, but this document carries a %s", a.ReceiptKind, f.kind)
	case a.ReceiptHash != f.hash:
		return fail("receipt_anchor names receipt hash %s, not this receipt's %s",
			truncate(a.ReceiptHash, 16), truncate(f.hash, 16))
	}
	leafErr := artifacts.ValidateReceiptLeafFields(f.kind, f.envelopeID, f.hash)
	want := artifacts.ComputeReceiptLeafHash(f.kind, f.envelopeID, f.hash)
	bound := "kind, envelope_id and hash"
	if v2 {
		leafErr = artifacts.ValidateReceiptLeafFieldsV2(f.kind, f.envelopeID, f.hash, d.RunID)
		want = artifacts.ComputeReceiptLeafHashV2(f.kind, f.envelopeID, f.hash, d.RunID)
		bound = "kind, envelope_id, hash and run_id"
	}
	if leafErr != nil {
		return fail("%v", leafErr)
	}
	if !strings.EqualFold(a.LeafHashHex, want) {
		return fail("the receipt leaf rebuilt from this document's %s is %s, not the anchored %s",
			bound, truncate(want, 16), truncate(a.LeafHashHex, 16))
	}
	if a.Backend != "rekor" {
		if required {
			return fail("this receipt seals anchor_required, but its receipt_anchor backend is %q, "+
				"not the public log", a.Backend)
		}
		rep.AllPassed, rep.VerdictTier = true, "SELF_CONSISTENT_NOT_ANCHORED"
		rep.Reason = fmt.Sprintf("receipt_anchor backend is %q: consistent, but not on a public log", a.Backend)
		return rep
	}
	// Error model of this binary: failures are the report itself.
	anchorErr := rekorAnchorVerifier(rekorverify.AnchorInput{
		LeafHashHex: a.LeafHashHex, EntryBody: a.EntryBody, LogIndex: a.LogIndex,
		TreeSize: a.TreeSize, RootHashHex: a.RootHashHex, InclusionPath: a.InclusionPath,
		Checkpoint: a.Checkpoint, LogID: a.LogID, LogEntryID: a.LogEntryID,
		IntegratedTime: a.IntegratedTime, SignedEntryTimestamp: a.SignedEntryTimestamp,
	})
	if anchorErr != nil {
		if stale, isStale := staleIndexReason(anchorErr, a.LogEntryID, a.LogIndex); isStale {
			rep.StaleEntryNumber = true
			return fail("the receipt's public-log entry: %s", stale)
		}
		return fail("the receipt's public-log entry does not verify: %v", anchorErr)
	}
	signer, signerErr := entrySignerOf(a.EntryBody)
	if signerErr != nil {
		return fail("the receipt's public-log entry has no valid signer: %v", signerErr)
	}
	rep.SignerFP = signer
	key, pinned := pinnedEntrySigners[signer]
	if !pinned {
		return fail("the receipt's public-log entry was logged by key %s, which is not a published "+
			"Verdifax log-signing key: anyone can add entries to the public log", truncate(signer, 16))
	}
	rep.SignerName = key.Name
	rep.AnchoredAt = utc(a.IntegratedTime)
	if !signerAcceptsAt(key, a.IntegratedTime) {
		return fail("the receipt's entry was logged at %s, outside the period in which %s is accepted",
			rep.AnchoredAt, key.Name)
	}
	clock, clockErr := time.Parse(time.RFC3339Nano, f.clock)
	if clockErr != nil {
		return fail("the receipt's clock %q is not an RFC 3339 time", safePrefix(f.clock))
	}
	gap := int64(float64(a.IntegratedTime) - float64(clock.UnixNano())/1e9)
	rep.GapSeconds = &gap
	rep.WindowSeconds = artifacts.ReceiptAnchoringWindowSeconds
	if float64(gap) < -anchoringClockSkew.Seconds() || gap > artifacts.ReceiptAnchoringWindowSeconds {
		return fail("the receipt's entry was logged at %s, outside the %d-second window after the "+
			"receipt's clock (%s): the entry was made later than the receipt claims",
			rep.AnchoredAt, artifacts.ReceiptAnchoringWindowSeconds, f.clock)
	}
	rep.Anchored, rep.AllPassed, rep.VerdictTier = true, true, "VERIFIED_ANCHORED"
	rep.RunIDBound = v2
	return rep
}

// issuedAfterAnchorRequired reports whether a receipt clock is at or
// after receiptAnchorRequiredSince. Error model: an unparseable clock
// is returned to the caller, which reports it as a failure.
func issuedAfterAnchorRequired(clock string) (bool, error) {
	t, parseErr := time.Parse(time.RFC3339Nano, clock)
	if parseErr != nil {
		return false, parseErr
	}
	since, sinceErr := time.Parse(time.RFC3339Nano, receiptAnchorRequiredSince)
	if sinceErr != nil {
		return false, sinceErr
	}
	return !t.Before(since), nil
}

// anchorRequiredOf returns the sealed anchor_required of the document's
// one receipt (factsOf has already required exactly one).
func anchorRequiredOf(d *artifacts.ReceiptDocument) bool {
	switch {
	case d.DenyReceipt != nil:
		return d.DenyReceipt.AnchorRequired
	case d.CCVHaltReceipt != nil:
		return d.CCVHaltReceipt.AnchorRequired
	case d.MACCHaltReceipt != nil:
		return d.MACCHaltReceipt.AnchorRequired
	case d.AivpT4HaltReceipt != nil:
		return d.AivpT4HaltReceipt.AnchorRequired
	case d.AttestationGapReceipt != nil:
		return d.AttestationGapReceipt.AnchorRequired
	}
	return false
}

func receiptExitShouldFail(r *ReceiptReport, allowUnanchored bool) bool {
	switch r.VerdictTier {
	case "VERIFIED_ANCHORED":
		return false
	case "SELF_CONSISTENT_NOT_ANCHORED":
		return !allowUnanchored
	}
	return true
}

func printReceiptReport(r *ReceiptReport) {
	fmt.Println("Verdifax receipt verification")
	runNote := "from the document, not checked"
	if r.RunIDBound {
		runNote = "bound by the public-log entry"
	}
	fmt.Printf("  Receipt:          %s, envelope %s\n", r.ReceiptKind, r.EnvelopeID)
	fmt.Printf("  Run:              %d (%s)\n", r.RunID, runNote)
	fmt.Printf("  Receipt clock:    %s\n", r.ReceiptClock)
	if r.HashOK {
		fmt.Printf("  Receipt hash:     ✓ recomputes from the receipt's own fields (%s)\n", truncate(r.ReceiptHash, 16))
	}
	if len(r.Summary) > 0 {
		fmt.Println("  Receipt says (the values checked; any viewer must show the same):")
		for _, k := range sortedKeys(r.Summary) {
			fmt.Printf("    %-22s %s\n", k+":", orNone(r.Summary[k]))
		}
	}
	if r.Anchored {
		fmt.Printf("  Public-log entry: ✓ %s, verified offline\n", r.AnchorLogEntry)
		fmt.Printf("  Logged by:        %s (%s)\n", r.SignerName, truncate(r.SignerFP, 16))
		fmt.Printf("  Logged at:        %s, %ds after the receipt's clock\n", r.AnchoredAt, *r.GapSeconds)
		fmt.Printf("  Anchoring window: %ds and met; a later re-log would fail\n", r.WindowSeconds)
		fmt.Printf("     View on https://search.sigstore.dev/?logIndex=%s\n", r.AnchorLogEntry)
	}
	switch r.VerdictTier {
	case "VERIFIED_ANCHORED":
		fmt.Println("VERDICT: ✓ RECEIPT VERIFIED AND ANCHORED")
	case "SELF_CONSISTENT_NOT_ANCHORED":
		fmt.Println("VERDICT: ⚠ RECEIPT SELF-CONSISTENT ONLY, NOT ANCHORED.")
		fmt.Printf("  %s. Its hash recomputing shows only that its fields agree with each other.\n",
			strings.TrimSuffix(r.Reason, "."))
	default:
		fmt.Printf("  Receipt:          ✗ FAILED · %s\n", r.Reason)
		fmt.Println("VERDICT: ✗ FAILED, at least one check did not pass (the ✗ line above says which).")
	}
}

func emitReceiptJSON(r *ReceiptReport) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

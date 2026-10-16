package artifacts

// Receipt anchoring (receipt anchor v1), the answer to round nine of
// the external review.
//
// A refused or halted run produces a sealed receipt (DenyReceipt,
// CCVHaltReceipt, MACCHaltReceipt, AivpT4HaltReceipt or
// AttestationGapReceipt) whose hash recomputes from its own fields.
// That shows the receipt is self-consistent, not who issued it or
// when: anyone can rewrite a receipt and recompute its hash. From
// verifier v0.13.0 a receipt carries receipt_anchor, one public-log
// entry whose leaf binds the receipt's kind, its envelope_id and its
// hash, signed with the Verdifax log-signing key. The verifier checks
// the entry exactly as it checks a run's entries (inclusion proof,
// signed checkpoint, entry body, signed entry timestamp, pinned
// signer) and requires it to have been logged within
// ReceiptAnchoringWindowSeconds after the receipt's own clock, so a
// receipt cannot be rewritten later and keep its date.
//
// The recipe below is frozen and byte-identical in the producing
// orchestrator and the public verifier.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	// ReceiptAnchorKind is receipt_anchor.kind.
	ReceiptAnchorKind = "verdifax.receipt_anchor.v1"
	// ReceiptLeafDomain is the domain tag of the receipt leaf.
	ReceiptLeafDomain = "verdifax.ledger.receipt.v1"
	// ReceiptAnchoringWindowSeconds is the window, fixed by the v1
	// recipe, within which a receipt's entry must be logged after the
	// receipt's own clock.
	ReceiptAnchoringWindowSeconds int64 = 600
)

// ReceiptKinds are the receipt kinds a receipt anchor may name; each is
// the JSON field the receipt is served under.
var ReceiptKinds = []string{
	"deny_receipt", "ccv_halt_receipt", "macc_halt_receipt",
	"aivp_t4_halt_receipt", "attestation_gap_receipt",
}

// ReceiptAnchor is a receipt's public-log entry. Field meanings match
// BundleAnchor: log_entry_id is the GLOBAL entry index, log_index the
// shard-local position the Merkle walk uses.
type ReceiptAnchor struct {
	Kind        string `json:"kind"`
	ReceiptKind string `json:"receipt_kind"`
	ReceiptHash string `json:"receipt_hash"`

	Backend              string   `json:"backend"`
	LogEntryID           string   `json:"log_entry_id"`
	LogID                string   `json:"log_id"`
	LeafHashHex          string   `json:"leaf_hash"`
	LogIndex             int64    `json:"log_index"`
	TreeSize             int64    `json:"tree_size"`
	RootHashHex          string   `json:"root_hash"`
	InclusionPath        []string `json:"inclusion_path"`
	Checkpoint           string   `json:"checkpoint"`
	SignedEntryTimestamp string   `json:"signed_entry_timestamp"`
	IntegratedTime       int64    `json:"integrated_time"`
	EntryBody            string   `json:"entry_body,omitempty"`
}

// ValidateReceiptLeafFields enforces the dot-join recipe's structural
// assumptions: a known kind, a dot-free non-empty envelope_id, and a
// 64-character lowercase hex receipt hash.
func ValidateReceiptLeafFields(kind, envelopeID, receiptHash string) error {
	known := false
	for _, k := range ReceiptKinds {
		if k == kind {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("receipt leaf: unknown receipt kind %q", kind)
	}
	if envelopeID == "" || strings.Contains(envelopeID, ".") {
		return fmt.Errorf("receipt leaf: envelope_id is empty or contains a dot; refusing to hash it")
	}
	if len(receiptHash) != 64 {
		return fmt.Errorf("receipt leaf: receipt hash must be 64 hex characters, got %d", len(receiptHash))
	}
	for _, c := range receiptHash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("receipt leaf: receipt hash must be lowercase hex")
		}
	}
	return nil
}

// ReceiptLeafPreimage is join(".", ReceiptLeafDomain, kind, envelopeID,
// receiptHash).
func ReceiptLeafPreimage(kind, envelopeID, receiptHash string) string {
	return strings.Join([]string{ReceiptLeafDomain, kind, envelopeID, receiptHash}, ".")
}

// ComputeReceiptLeafHash returns hex(sha256(ReceiptLeafPreimage(...))).
func ComputeReceiptLeafHash(kind, envelopeID, receiptHash string) string {
	sum := sha256.Sum256([]byte(ReceiptLeafPreimage(kind, envelopeID, receiptHash)))
	return hex.EncodeToString(sum[:])
}

// Receipt anchor v2 (round ten of the external review). A v1 leaf binds
// the receipt's kind, envelope_id and hash but not the run it belongs
// to, so a genuine receipt document could be relabelled with another
// run_id and still verify. The v2 leaf also binds the run_id the API
// assigned, and every receipt anchored under v2 seals anchor_required
// in its own hash, so deleting the anchor fails rather than
// downgrades. The window is unchanged.
const (
	// ReceiptAnchorKindV2 is receipt_anchor.kind for a v2 anchor.
	ReceiptAnchorKindV2 = "verdifax.receipt_anchor.v2"
	// ReceiptLeafDomainV2 is the domain tag of the v2 receipt leaf.
	ReceiptLeafDomainV2 = "verdifax.ledger.receipt.v2"
)

// ValidateReceiptLeafFieldsV2 applies the v1 checks and requires a
// positive run_id.
func ValidateReceiptLeafFieldsV2(kind, envelopeID, receiptHash string, runID int64) error {
	if v1Err := ValidateReceiptLeafFields(kind, envelopeID, receiptHash); v1Err != nil {
		return v1Err
	}
	if runID <= 0 {
		return fmt.Errorf("receipt leaf: run_id must be positive, got %d", runID)
	}
	return nil
}

// ReceiptLeafPreimageV2 is join(".", ReceiptLeafDomainV2, kind,
// envelopeID, receiptHash, decimal runID).
func ReceiptLeafPreimageV2(kind, envelopeID, receiptHash string, runID int64) string {
	return strings.Join([]string{ReceiptLeafDomainV2, kind, envelopeID, receiptHash,
		strconv.FormatInt(runID, 10)}, ".")
}

// ComputeReceiptLeafHashV2 returns hex(sha256(ReceiptLeafPreimageV2(...))).
func ComputeReceiptLeafHashV2(kind, envelopeID, receiptHash string, runID int64) string {
	sum := sha256.Sum256([]byte(ReceiptLeafPreimageV2(kind, envelopeID, receiptHash, runID)))
	return hex.EncodeToString(sum[:])
}

// ReceiptDocument is the JSON the Verdifax API serves for a refused or
// halted run's receipt (GET /runs/{id}/deny-receipt and its siblings):
// exactly one receipt, and its receipt_anchor when one was made.
type ReceiptDocument struct {
	OK                    bool                   `json:"ok"`
	RunID                 int64                  `json:"run_id"`
	DenyReceipt           *DenyReceipt           `json:"deny_receipt,omitempty"`
	CCVHaltReceipt        *CCVHaltReceipt        `json:"ccv_halt_receipt,omitempty"`
	MACCHaltReceipt       *MACCHaltReceipt       `json:"macc_halt_receipt,omitempty"`
	AivpT4HaltReceipt     *AivpT4HaltReceipt     `json:"aivp_t4_halt_receipt,omitempty"`
	AttestationGapReceipt *AttestationGapReceipt `json:"attestation_gap_receipt,omitempty"`
	ReceiptAnchor         *ReceiptAnchor         `json:"receipt_anchor,omitempty"`
}

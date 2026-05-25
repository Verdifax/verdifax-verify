package artifacts

// CCVHaltReceipt is the sealed cryptographic artifact CCV emits when
// runtime budget enforcement halts a pipeline mid-execution. It is the
// continuous-constraint counterpart to DenyReceipt:
//
//   - DenyReceipt: proves "this was correctly prevented at admission"
//   - CCVHaltReceipt, proves "this was correctly halted mid-execution"
//
// Both share the same canonical-bytes + SHA-256 sealing machinery, the
// same independent-verifier API, and the same chain-of-custody binding , 
// the trio (AllowToken, DenyReceipt, CCVHaltReceipt) plus MCDFinding
// gives Phase 11 four artifact-typed outcomes for any orchestrated run:
//
//   - allowed and completed       → AllowToken + .VFA
//   - prevented at admission      → DenyReceipt
//   - admitted but halted by CCV  → AllowToken + CCVHaltReceipt
//   - signature/provenance fail   → DenyReceipt + MCDFinding
//
// Field order is intentionally lexicographic so encoding/json's stable
// serialization produces canonical bytes that match the spec's RFC-8785
// representation. Do not reorder fields without bumping the artifact
// version (currently "vfa.ccv_halt.v1").
type CCVHaltReceipt struct {
	// AllowTokenHash is the §0-compliant hash of the AllowToken that
	// initially authorized this run. The CCV halt happened DESPITE the
	// allow because runtime budgets were breached, binding the original
	// allow into the halt receipt preserves the full causal chain.
	AllowTokenHash string `json:"allow_token_hash"`

	// BudgetHash is the SHA-256 hex of the active CCVBudget's canonical
	// preimage. Lets audits prove which budget configuration was in
	// force at halt time.
	BudgetHash string `json:"budget_hash"`

	// BudgetLimit is the specific limit value that was breached
	// (e.g., max_tokens=1000). Type is the constraint discriminator
	// (token / time / cost). Together they make the halt cause readable.
	BudgetLimit int64 `json:"budget_limit"`

	// ConstraintType identifies which budget dimension was breached.
	// One of: "token_budget", "time_budget", "cost_budget".
	ConstraintType string `json:"constraint_type"`

	// ConsumedAtHalt is the actual measured consumption at the moment
	// CCV decided to halt. Must satisfy ConsumedAtHalt >= BudgetLimit
	// for any valid halt receipt.
	ConsumedAtHalt int64 `json:"consumed_at_halt"`

	// EnvelopeID identifies the EnvelopeV2 whose execution was halted.
	// From DOG output.
	EnvelopeID string `json:"envelope_id"`

	// EvaluatorVersion is the CCV monitor software version that decided
	// to halt. Format: "ccv-X.Y.Z".
	EvaluatorVersion string `json:"evaluator_version"`

	// HaltClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// halt was sealed.
	HaltClock string `json:"halt_clock"`

	// HaltReasonCode is the standardized code identifying why CCV halted.
	// One of: "TOKEN_BUDGET_EXCEEDED", "TIME_BUDGET_EXCEEDED",
	// "COST_BUDGET_EXCEEDED".
	HaltReasonCode string `json:"halt_reason_code"`

	// PartialExecutionHash is the §0-compliant hash of whatever execution
	// state existed at halt time (e.g., the EFA hash from DKEC if DKEC
	// completed before CCV halted, empty string if the halt was pre-DKEC).
	// Captures WHAT had been executed without storing the raw execution.
	PartialExecutionHash string `json:"partial_execution_hash"`

	// Version is always "vfa.ccv_halt.v1" for this artifact version.
	Version string `json:"version"`

	// Hash is the canonical SHA-256 hex of the ten preimage fields
	// above. Filled by BuildCCVHaltReceiptHash; this field is NOT part
	// of the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// BuildCCVHaltReceiptHash computes the canonical hash of the receipt's
// preimage and populates the Hash field. The receipt argument is mutated
// in place; the resulting Hash is also returned for convenience.
func BuildCCVHaltReceiptHash(receipt *CCVHaltReceipt) (string, error) {
	preimage := struct {
		AllowTokenHash       string `json:"allow_token_hash"`
		BudgetHash           string `json:"budget_hash"`
		BudgetLimit          int64  `json:"budget_limit"`
		ConstraintType       string `json:"constraint_type"`
		ConsumedAtHalt       int64  `json:"consumed_at_halt"`
		EnvelopeID           string `json:"envelope_id"`
		EvaluatorVersion     string `json:"evaluator_version"`
		HaltClock            string `json:"halt_clock"`
		HaltReasonCode       string `json:"halt_reason_code"`
		PartialExecutionHash string `json:"partial_execution_hash"`
		Version              string `json:"version"`
	}{
		AllowTokenHash:       receipt.AllowTokenHash,
		BudgetHash:           receipt.BudgetHash,
		BudgetLimit:          receipt.BudgetLimit,
		ConstraintType:       receipt.ConstraintType,
		ConsumedAtHalt:       receipt.ConsumedAtHalt,
		EnvelopeID:           receipt.EnvelopeID,
		EvaluatorVersion:     receipt.EvaluatorVersion,
		HaltClock:            receipt.HaltClock,
		HaltReasonCode:       receipt.HaltReasonCode,
		PartialExecutionHash: receipt.PartialExecutionHash,
		Version:              receipt.Version,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	receipt.Hash = hash
	return hash, nil
}

// VerifyCCVHaltReceiptHash recomputes the receipt's canonical hash from
// its preimage fields and compares to the stored Hash field. Returns nil
// on match, an error describing the mismatch otherwise.
//
// This is what an extended verdifax-pepg-verify would call to validate
// independently-submitted CCVHaltReceipts.
func VerifyCCVHaltReceiptHash(receipt *CCVHaltReceipt) error {
	expected := receipt.Hash
	receipt.Hash = ""
	defer func() { receipt.Hash = expected }()
	actual, err := BuildCCVHaltReceiptHash(receipt)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrCCVHaltReceiptHashMismatch
	}
	return nil
}

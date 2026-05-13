package artifacts

// MACCHaltReceipt is the sealed cryptographic artifact MACC emits when
// cumulative cross-run budget enforcement halts a pipeline. It is the
// multi-agent counterpart to CCVHaltReceipt:
//
//   - CCVHaltReceipt   — proves "this run exceeded its per-run budget"
//   - MACCHaltReceipt — proves "this tenant exceeded its cumulative budget"
//
// MACC is the only artifact-producing stage that depends on STATE
// SHARED ACROSS RUNS — every prior CCVHaltReceipt and AllowToken in the
// current window contributed to the cumulative counter that this halt
// references. The receipt names the window + the cumulative consumption
// at halt time so audits can reconstruct exactly which prior runs
// contributed.
//
// Field order is intentionally lexicographic so encoding/json's stable
// serialization produces canonical bytes that match the spec's RFC-8785
// representation. Do not reorder fields without bumping the artifact
// version (currently "vfa.macc_halt.v1").
type MACCHaltReceipt struct {
	// AllowTokenHash is the §0-compliant hash of the AllowToken that
	// initially authorized the run that triggered this halt. The MACC
	// halt happened DESPITE the per-run allow + per-run CCV pass because
	// cumulative budgets were breached.
	AllowTokenHash string `json:"allow_token_hash"`

	// BudgetHash is the SHA-256 hex of the active MACCBudget's canonical
	// preimage. Lets audits prove which cumulative budget configuration
	// was in force at halt time.
	BudgetHash string `json:"budget_hash"`

	// BudgetLimit is the cumulative limit that was breached
	// (e.g., max_cumulative_tokens=100000 for a tenant per day).
	BudgetLimit int64 `json:"budget_limit"`

	// ConstraintType identifies which cumulative dimension was breached.
	// One of: "cumulative_token_budget", "cumulative_cost_budget".
	ConstraintType string `json:"constraint_type"`

	// CumulativeAtHalt is the actual cumulative consumption at halt time,
	// across ALL runs in the current window for the bound TenantID.
	// Must satisfy CumulativeAtHalt >= BudgetLimit for any valid receipt.
	CumulativeAtHalt int64 `json:"cumulative_at_halt"`

	// EnvelopeID identifies the EnvelopeV2 of the run that tipped the
	// cumulative counter over the limit. From DOG output.
	EnvelopeID string `json:"envelope_id"`

	// EvaluatorVersion is the MACC coordinator software version that
	// decided to halt. Format: "macc-X.Y.Z".
	EvaluatorVersion string `json:"evaluator_version"`

	// HaltClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// halt was sealed.
	HaltClock string `json:"halt_clock"`

	// HaltReasonCode is the standardized code identifying why MACC halted.
	// One of: "CUMULATIVE_TOKEN_BUDGET_EXCEEDED",
	//         "CUMULATIVE_COST_BUDGET_EXCEEDED".
	HaltReasonCode string `json:"halt_reason_code"`

	// PerRunConsumption is what THIS run contributed to the cumulative
	// counter (i.e., the CCV-reported consumption for this envelope).
	// Useful for forensics — combined with cumulative-at-halt the auditor
	// can compute "the cumulative was N before this run; this run added M".
	PerRunConsumption int64 `json:"per_run_consumption"`

	// TenantID is the operator-defined coordination key. All runs sharing
	// this TenantID accumulate against the same cumulative budget.
	// Typically a customer/organization identifier.
	TenantID string `json:"tenant_id"`

	// Version is always "vfa.macc_halt.v1" for this artifact version.
	Version string `json:"version"`

	// WindowStart is the RFC 3339 UTC timestamp marking the start of the
	// rollup window the cumulative counter was tracking. Auditors use
	// this + the receipt's HaltClock to reconstruct which prior runs
	// in the window contributed to the cumulative counter.
	WindowStart string `json:"window_start"`

	// Hash is the canonical SHA-256 hex of the twelve preimage fields
	// above. Filled by BuildMACCHaltReceiptHash; this field is NOT part
	// of the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// BuildMACCHaltReceiptHash computes the canonical hash of the receipt's
// preimage and populates the Hash field. The receipt argument is mutated
// in place; the resulting Hash is also returned for convenience.
func BuildMACCHaltReceiptHash(receipt *MACCHaltReceipt) (string, error) {
	preimage := struct {
		AllowTokenHash    string `json:"allow_token_hash"`
		BudgetHash        string `json:"budget_hash"`
		BudgetLimit       int64  `json:"budget_limit"`
		ConstraintType    string `json:"constraint_type"`
		CumulativeAtHalt  int64  `json:"cumulative_at_halt"`
		EnvelopeID        string `json:"envelope_id"`
		EvaluatorVersion  string `json:"evaluator_version"`
		HaltClock         string `json:"halt_clock"`
		HaltReasonCode    string `json:"halt_reason_code"`
		PerRunConsumption int64  `json:"per_run_consumption"`
		TenantID          string `json:"tenant_id"`
		Version           string `json:"version"`
		WindowStart       string `json:"window_start"`
	}{
		AllowTokenHash:    receipt.AllowTokenHash,
		BudgetHash:        receipt.BudgetHash,
		BudgetLimit:       receipt.BudgetLimit,
		ConstraintType:    receipt.ConstraintType,
		CumulativeAtHalt:  receipt.CumulativeAtHalt,
		EnvelopeID:        receipt.EnvelopeID,
		EvaluatorVersion:  receipt.EvaluatorVersion,
		HaltClock:         receipt.HaltClock,
		HaltReasonCode:    receipt.HaltReasonCode,
		PerRunConsumption: receipt.PerRunConsumption,
		TenantID:          receipt.TenantID,
		Version:           receipt.Version,
		WindowStart:       receipt.WindowStart,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	receipt.Hash = hash
	return hash, nil
}

// VerifyMACCHaltReceiptHash recomputes the receipt's canonical hash from
// its preimage fields and compares to the stored Hash field. Returns nil
// on match, an error describing the mismatch otherwise.
func VerifyMACCHaltReceiptHash(receipt *MACCHaltReceipt) error {
	expected := receipt.Hash
	receipt.Hash = ""
	defer func() { receipt.Hash = expected }()
	actual, err := BuildMACCHaltReceiptHash(receipt)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrMACCHaltReceiptHashMismatch
	}
	return nil
}

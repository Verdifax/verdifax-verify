package artifacts

// AivpT4HaltReceipt is the sealed cryptographic artifact AIVP-T4 emits
// when the Tier-4 governance pipeline returns a non-RELEASE decision
// (DENY / HALT / DEFER) on the AI output text bound to a run.
//
// Fits into the Phase 10/11/12 sealed-artifact family:
//
//   - DenyReceipt        — pre-execution policy halted at admission
//   - CCVHaltReceipt     — runtime budget exceeded mid-execution
//   - MACCHaltReceipt    — cumulative cross-run budget exceeded
//   - AivpT4HaltReceipt  — Tier-4 governance refused to RELEASE the AI output
//
// All five share the same canonical-bytes + SHA-256 sealing machinery,
// the same independent-verifier API, and the same chain-of-custody
// binding to the originating envelope + AllowToken (when present).
//
// What's bound into this seal:
//   - The PIA (Proof Integrity Audit) hash from AIVP_T4 — the canonical
//     T4 governance seal over the model invocation, the cognitive-state
//     snapshot, the contradiction check, the policy evaluation, and the
//     enforcement decision.
//   - The AivpT4 adapter identity ("mock-claude" / "live-claude-api" /
//     etc.) so the verifier can dispatch to the right validator and so
//     the audit trail names which adapter ran the governance.
//   - The decision kind ("deny" / "halt" / "defer") and adapter-reported
//     decision-reason summary.
//   - The hash of the AI output text the governance pipeline ran on, so
//     the chain-of-custody extends from the caller's input through the
//     halt without storing the raw text in the receipt.
//
// Field order is intentionally lexicographic so encoding/json's stable
// serialization produces canonical bytes that match the spec's RFC-8785
// representation. Do not reorder fields without bumping the artifact
// version (currently "vfa.aivp_t4_halt.v1").
type AivpT4HaltReceipt struct {
	// AdapterID identifies which AIVP-T4 ModelAdapter produced the
	// governance decision — e.g., "mock-claude", "live-claude-api". The
	// verifier can use this to scope its trust evaluation: a mock-mode
	// halt receipt should NOT be presented to a third party as evidence
	// the run was governed by a real model.
	AdapterID string `json:"adapter_id"`

	// AiOutputHash is the §0-compliant SHA-256 of the AI output text the
	// governance pipeline evaluated. Lets a third party recompute the
	// hash from the original text and confirm the receipt is bound to
	// this exact piece of model output, not a substitute.
	AiOutputHash string `json:"ai_output_hash"`

	// AllowTokenHash is the §0-compliant hash of the AllowToken that
	// initially admitted this run (when PEPG ran). The AIVP-T4 halt
	// happened DESPITE the allow because Tier-4 governance refused to
	// release the AI output — binding the original allow into the halt
	// receipt preserves the full causal chain. Empty string when PEPG
	// was not wired or skipped.
	AllowTokenHash string `json:"allow_token_hash"`

	// DecisionKind identifies which negative outcome AIVP-T4 returned.
	// One of: "deny", "halt", "defer". RELEASE outcomes don't produce
	// a halt receipt (the run continues) so they're never represented
	// here.
	DecisionKind string `json:"decision_kind"`

	// DecisionReason is the adapter-supplied human-readable summary
	// of why the governance pipeline produced this decision. Free-form
	// string sourced from the AIVP-T4 governance output (e.g., a
	// contradiction-detection note, a policy-violation summary, a
	// cognition-validation failure description).
	DecisionReason string `json:"decision_reason"`

	// EnvelopeID identifies the EnvelopeV2 whose execution was halted.
	// From DOG output.
	EnvelopeID string `json:"envelope_id"`

	// EvaluatorVersion is the AIVP-T4 governor software version that
	// decided to halt. Format: "aivp-t4-X.Y.Z".
	EvaluatorVersion string `json:"evaluator_version"`

	// HaltClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// halt was sealed.
	HaltClock string `json:"halt_clock"`

	// HaltReasonCode is the standardized machine-readable code identifying
	// why AIVP-T4 halted. One of: "AIVP_T4_DENY", "AIVP_T4_HALT",
	// "AIVP_T4_DEFER".
	HaltReasonCode string `json:"halt_reason_code"`

	// PiaHash is the AIVP-T4 Proof Integrity Audit hash — the canonical
	// T4 governance seal binding the cognitive state snapshot, the
	// contradiction check, the cognition validation, the policy
	// evaluation, and the enforcement action into a single sealed
	// hash. This is the AIVP-T4-internal seal; the AivpT4HaltReceipt
	// hash binds this PIA hash plus the orchestrator-side context
	// (envelope, allow token, ai-output) into the orchestrator-level
	// audit chain.
	PiaHash string `json:"pia_hash"`

	// Version is always "vfa.aivp_t4_halt.v1" for this artifact version.
	Version string `json:"version"`

	// Hash is the canonical SHA-256 hex of the ten preimage fields
	// above. Filled by BuildAivpT4HaltReceiptHash; this field is NOT
	// part of the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// BuildAivpT4HaltReceiptHash computes the canonical hash of the receipt's
// preimage and populates the Hash field. The receipt argument is mutated
// in place; the resulting Hash is also returned for convenience.
func BuildAivpT4HaltReceiptHash(receipt *AivpT4HaltReceipt) (string, error) {
	preimage := struct {
		AdapterID        string `json:"adapter_id"`
		AiOutputHash     string `json:"ai_output_hash"`
		AllowTokenHash   string `json:"allow_token_hash"`
		DecisionKind     string `json:"decision_kind"`
		DecisionReason   string `json:"decision_reason"`
		EnvelopeID       string `json:"envelope_id"`
		EvaluatorVersion string `json:"evaluator_version"`
		HaltClock        string `json:"halt_clock"`
		HaltReasonCode   string `json:"halt_reason_code"`
		PiaHash          string `json:"pia_hash"`
		Version          string `json:"version"`
	}{
		AdapterID:        receipt.AdapterID,
		AiOutputHash:     receipt.AiOutputHash,
		AllowTokenHash:   receipt.AllowTokenHash,
		DecisionKind:     receipt.DecisionKind,
		DecisionReason:   receipt.DecisionReason,
		EnvelopeID:       receipt.EnvelopeID,
		EvaluatorVersion: receipt.EvaluatorVersion,
		HaltClock:        receipt.HaltClock,
		HaltReasonCode:   receipt.HaltReasonCode,
		PiaHash:          receipt.PiaHash,
		Version:          receipt.Version,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	receipt.Hash = hash
	return hash, nil
}

// VerifyAivpT4HaltReceiptHash recomputes the receipt's canonical hash
// from its preimage fields and compares to the stored Hash field.
// Returns nil on match, an error describing the mismatch otherwise.
//
// This is what an extended verdifax-pepg-verify (or a dedicated
// verdifax-aivp-verify) would call to validate independently-submitted
// AivpT4HaltReceipts.
func VerifyAivpT4HaltReceiptHash(receipt *AivpT4HaltReceipt) error {
	expected := receipt.Hash
	receipt.Hash = ""
	defer func() { receipt.Hash = expected }()
	actual, err := BuildAivpT4HaltReceiptHash(receipt)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrAivpT4HaltReceiptHashMismatch
	}
	return nil
}

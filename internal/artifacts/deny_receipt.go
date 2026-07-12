package artifacts

// DenyReceipt is the sealed cryptographic artifact PEPG emits when policy
// evaluation produces a deny outcome. It is the prevention-side counterpart
// to the .VFA artifact: where .VFA proves "this AI execution happened
// correctly," DenyReceipt proves "this AI execution was correctly prevented
// from happening at all."
//
// See BUILDING DOCS/DENY_RECEIPT_SCHEMA_V0.md for the full specification.
//
// Field order is intentionally lexicographic so encoding/json's stable
// serialization produces canonical bytes that match the spec's RFC-8785
// representation. Do not reorder fields without bumping the artifact
// version (currently "vfa.deny_receipt.v1").
type DenyReceipt struct {
	// DecisionReasonCode is one of the standardized reason codes from
	// PEPG_PSL_SPEC_V0.md §11. Examples: "RULE_DENIED", "RULE_ALLOWED",
	// "DEFAULT_EFFECT_APPLIED", "CLASSIFICATION_EXCEEDED",
	// "MFA_REQUIRED_NOT_SATISFIED", "MCD_SIGNATURE_MATCH",
	// "MCD_PROVENANCE_FAILURE".
	DecisionReasonCode string `json:"decision_reason_code"`

	// DenyClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// deny was sealed. Conformant to §0 clock spec.
	DenyClock string `json:"deny_clock"`

	// EnvelopeID identifies the EnvelopeV2 that was denied. From DOG output.
	EnvelopeID string `json:"envelope_id"`

	// EvaluationHash binds envelope + policy + rule + outcome.
	// SHA-256 hex per PEPG_PSL_SPEC_V0.md §8.2.
	EvaluationHash string `json:"evaluation_hash"`

	// EvaluatorVersion is the PEPG software version that made the call.
	// Format: "pepg-X.Y.Z".
	EvaluatorVersion string `json:"evaluator_version"`

	// FiredRuleID is the rule_id of the rule that fired with effect=deny,
	// or exactly "default" when default_effect=deny was applied.
	FiredRuleID string `json:"fired_rule_id"`

	// MCDFindingHash references the MCD finding artifact's hash when the
	// deny was driven by Malicious Code Defense. Empty string when the
	// deny was driven only by PSL rule evaluation without MCD involvement.
	MCDFindingHash string `json:"mcd_finding_hash"`

	// PolicyHash is the SHA-256 of the active policy at deny time.
	// Per PEPG_PSL_SPEC_V0.md §8.1.
	PolicyHash string `json:"policy_hash"`

	// Version is always "vfa.deny_receipt.v1" for this artifact version.
	Version string `json:"version"`

	// Hash is the canonical SHA-256 hex of the eight preimage fields
	// above. Filled by BuildDenyReceiptHash; this field is NOT part of
	// the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// BuildDenyReceiptHash computes the canonical hash of the receipt's
// preimage and populates the Hash field. The receipt argument is mutated
// in place; the resulting Hash is also returned for convenience.
//
// The hash is CanonicalHash() over the nine preimage fields (every
// field except Hash itself), in canonical struct order. Covered by
// deny_receipt_test.go with a frozen known-answer golden hash.
func BuildDenyReceiptHash(receipt *DenyReceipt) (string, error) {
	preimage := struct {
		DecisionReasonCode string `json:"decision_reason_code"`
		DenyClock          string `json:"deny_clock"`
		EnvelopeID         string `json:"envelope_id"`
		EvaluationHash     string `json:"evaluation_hash"`
		EvaluatorVersion   string `json:"evaluator_version"`
		FiredRuleID        string `json:"fired_rule_id"`
		MCDFindingHash     string `json:"mcd_finding_hash"`
		PolicyHash         string `json:"policy_hash"`
		Version            string `json:"version"`
	}{
		DecisionReasonCode: receipt.DecisionReasonCode,
		DenyClock:          receipt.DenyClock,
		EnvelopeID:         receipt.EnvelopeID,
		EvaluationHash:     receipt.EvaluationHash,
		EvaluatorVersion:   receipt.EvaluatorVersion,
		FiredRuleID:        receipt.FiredRuleID,
		MCDFindingHash:     receipt.MCDFindingHash,
		PolicyHash:         receipt.PolicyHash,
		Version:            receipt.Version,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	receipt.Hash = hash
	return hash, nil
}

// VerifyDenyReceiptHash recomputes the receipt's canonical hash from its
// preimage fields and compares to the stored Hash field. Returns nil on
// match, an error describing the mismatch otherwise.
//
// This is what the standalone verdifax-deny-verifier (planned per spec
// §8) will call to validate independently-submitted DenyReceipts.
func VerifyDenyReceiptHash(receipt *DenyReceipt) error {
	expected := receipt.Hash
	receipt.Hash = ""
	defer func() { receipt.Hash = expected }()
	actual, err := BuildDenyReceiptHash(receipt)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrDenyReceiptHashMismatch
	}
	return nil
}

// DenySidecar is the human-readable advisory document emitted alongside
// the sealed DenyReceipt. It is NOT sealed and NOT part of the receipt's
// hash; it carries the explanation a human operator needs without
// inflating the cryptographic seal.
//
// See BUILDING DOCS/DENY_RECEIPT_SCHEMA_V0.md §3 for the rationale.
type DenySidecar struct {
	Kind             string                  `json:"kind"` // "verdifax.artifact.deny_sidecar.v1"
	EnvelopeID       string                  `json:"envelope_id"`
	DenyReceiptHash  string                  `json:"deny_receipt_hash"`
	DenyReasonText   string                  `json:"deny_reason_text"`
	EvaluationTrace  []EvaluationTraceEntry  `json:"evaluation_trace,omitempty"`
	MCDFindingDetail *MCDFindingDetail       `json:"mcd_finding_detail,omitempty"`
}

// EvaluationTraceEntry is one rule's evaluation result captured in the
// advisory sidecar. Recomputable deterministically from envelope + policy.
type EvaluationTraceEntry struct {
	RuleID   string `json:"rule_id"`
	Matched  bool   `json:"matched"`
	FailedOn string `json:"failed_on,omitempty"` // e.g. "verb_mismatch", "classification_max"
}

// MCDFindingDetail is the human-readable detail of an MCD signature hit
// included in the deny sidecar (not the sealed receipt).
type MCDFindingDetail struct {
	SignatureID     string `json:"signature_id"`
	SignatureName   string `json:"signature_name"`
	MatchedText     string `json:"matched_text"`
	Severity        string `json:"severity"`
	SourceCitation  string `json:"source_citation"`
}

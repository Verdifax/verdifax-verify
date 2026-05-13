package artifacts

// AllowToken is the sealed cryptographic artifact PEPG emits when policy
// evaluation produces an allow outcome. It is the authorization-side
// counterpart to DenyReceipt: where DenyReceipt proves "this AI execution
// was correctly prevented from happening," AllowToken proves "this AI
// execution was correctly authorized to proceed."
//
// Both artifacts share the same canonical-bytes + SHA-256 sealing
// machinery, the same independent-verifier API (Verify*Hash), and the
// same chain-of-custody binding — same §0 guarantees, just with
// asymmetric outcomes. The pair completes the prevention/authorization
// symmetry the patent claim depends on.
//
// Field order is intentionally lexicographic so encoding/json's stable
// serialization produces canonical bytes that match the spec's RFC-8785
// representation. Do not reorder fields without bumping the artifact
// version (currently "vfa.allow_token.v1").
type AllowToken struct {
	// AllowClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// allow was sealed. Conformant to §0 clock spec.
	AllowClock string `json:"allow_clock"`

	// DecisionReasonCode is one of the standardized reason codes from
	// PEPG_PSL_SPEC_V0.md §11. For allow tokens this is typically
	// "RULE_ALLOWED"; the field is preserved (rather than implied) so
	// future per-rule overrides can stamp more specific authorization
	// reasons without changing the artifact schema.
	DecisionReasonCode string `json:"decision_reason_code"`

	// EnvelopeID identifies the EnvelopeV2 that was authorized. From DOG output.
	EnvelopeID string `json:"envelope_id"`

	// EvaluationHash binds envelope + policy + rule + outcome.
	// SHA-256 hex per PEPG_PSL_SPEC_V0.md §8.2.
	EvaluationHash string `json:"evaluation_hash"`

	// EvaluatorVersion is the PEPG software version that made the call.
	// Format: "pepg-X.Y.Z". Lets future audits attribute the decision to
	// a specific evaluator implementation.
	EvaluatorVersion string `json:"evaluator_version"`

	// FiredRuleID is the rule_id of the rule that fired with effect=allow.
	// Always a real rule_id (not "default") for allow tokens — the v0
	// PSL grammar's only path to allow is an explicit allow rule. A
	// future deny-by-default policy with no allow rules cannot produce
	// an AllowToken.
	FiredRuleID string `json:"fired_rule_id"`

	// PolicyHash is the SHA-256 of the active policy at allow time.
	// Per PEPG_PSL_SPEC_V0.md §8.1.
	PolicyHash string `json:"policy_hash"`

	// Version is always "vfa.allow_token.v1" for this artifact version.
	Version string `json:"version"`

	// Hash is the canonical SHA-256 hex of the eight preimage fields
	// above. Filled by BuildAllowTokenHash; this field is NOT part of
	// the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// BuildAllowTokenHash computes the canonical hash of the token's
// preimage and populates the Hash field. The token argument is mutated
// in place; the resulting Hash is also returned for convenience.
func BuildAllowTokenHash(token *AllowToken) (string, error) {
	preimage := struct {
		AllowClock         string `json:"allow_clock"`
		DecisionReasonCode string `json:"decision_reason_code"`
		EnvelopeID         string `json:"envelope_id"`
		EvaluationHash     string `json:"evaluation_hash"`
		EvaluatorVersion   string `json:"evaluator_version"`
		FiredRuleID        string `json:"fired_rule_id"`
		PolicyHash         string `json:"policy_hash"`
		Version            string `json:"version"`
	}{
		AllowClock:         token.AllowClock,
		DecisionReasonCode: token.DecisionReasonCode,
		EnvelopeID:         token.EnvelopeID,
		EvaluationHash:     token.EvaluationHash,
		EvaluatorVersion:   token.EvaluatorVersion,
		FiredRuleID:        token.FiredRuleID,
		PolicyHash:         token.PolicyHash,
		Version:            token.Version,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	token.Hash = hash
	return hash, nil
}

// VerifyAllowTokenHash recomputes the token's canonical hash from its
// preimage fields and compares to the stored Hash field. Returns nil on
// match, an error describing the mismatch otherwise.
//
// This is what the standalone verdifax-pepg-verify (Day 13) calls to
// validate independently-submitted AllowTokens.
func VerifyAllowTokenHash(token *AllowToken) error {
	expected := token.Hash
	token.Hash = ""
	defer func() { token.Hash = expected }()
	actual, err := BuildAllowTokenHash(token)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrAllowTokenHashMismatch
	}
	return nil
}

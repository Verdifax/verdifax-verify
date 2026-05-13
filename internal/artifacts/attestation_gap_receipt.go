package artifacts

import (
	"errors"
	"sort"
)

// AttestationGapReceipt is the sealed cryptographic artifact PEPG emits
// when admission halts because the active policy required attested
// fields the caller didn't declare. It is the semantic-completeness-side
// counterpart to DenyReceipt:
//
//   - DenyReceipt = "policy refused this run" (rule fired with effect=deny)
//   - AttestationGapReceipt = "policy required X but caller didn't declare X"
//
// Both produce sealed audit artifacts that carry the same chain-of-custody
// guarantees: canonical bytes → SHA-256 hash → independently re-derivable
// by anyone holding the policy + the missing-fields list.
//
// Why a separate artifact: conflating "policy refused" with "attestation
// incomplete" makes audit trails harder to reason about. A regulated
// buyer's compliance officer reading a denial wants to know whether
// they need to update a rule (denied by policy) vs. update their caller
// integration (didn't declare a required field). Distinct artifacts
// give distinct remediation paths.
//
// Field order is intentionally lexicographic so encoding/json's stable
// serialization produces canonical bytes that match the RFC-8785
// representation. Do not reorder fields without bumping the artifact
// version (currently "vfa.attestation_gap_receipt.v1").
type AttestationGapReceipt struct {
	// DecisionReasonCode is always psl.ReasonAttestationGap
	// ("ATTESTATION_GAP") for this artifact. Carried as a field rather
	// than implied by Version so the schema matches DenyReceipt for
	// readers that switch on decision_reason_code.
	DecisionReasonCode string `json:"decision_reason_code"`

	// EnvelopeID identifies the EnvelopeV2 that was halted at admission.
	// Phase-18 admission halts before DOG completes the full envelope,
	// so this may be the partial envelope ID computed from the request
	// payload + program_id + route_id. The chain-of-custody guarantee
	// is "this exact request, identified by this exact ID, was halted
	// because of these missing fields" — not full envelope semantics.
	EnvelopeID string `json:"envelope_id"`

	// EvaluatorVersion is the PEPG software version that made the gap
	// determination. Format: "pepg-X.Y.Z". Same shape as DenyReceipt.
	EvaluatorVersion string `json:"evaluator_version"`

	// GapClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// gap was sealed. Conformant to §0 clock spec. Mirror of
	// DenyReceipt.DenyClock for time-ordered auditing.
	GapClock string `json:"gap_clock"`

	// MissingFields is the sorted list of canonical attested-field names
	// the caller did not declare. Always a subset of RequiredFields.
	// Sorted ascending so the canonical preimage is deterministic.
	// Encoded as a JSON array of strings.
	MissingFields []string `json:"missing_fields"`

	// PolicyHash is the SHA-256 of the active policy at gap time.
	// Per PEPG_PSL_SPEC_V0.md §8.1 (extended in Phase 18 to bind
	// required_attested_fields, required_outcome_fields, and
	// profile_tag into the canonical preimage).
	PolicyHash string `json:"policy_hash"`

	// PolicyID is the human-readable identifier from the active
	// policy document. Surfaced on the receipt so a buyer reading the
	// denial knows which policy was being enforced without resolving
	// PolicyHash to the policy bytes separately.
	PolicyID string `json:"policy_id"`

	// PolicyName is the human-readable display name from the active
	// policy. Same audience as PolicyID; both are bound into the
	// receipt hash so tampering with either invalidates the seal.
	PolicyName string `json:"policy_name"`

	// ProfileTag is the optional starter-profile tag the policy
	// declared (e.g. "healthcare_baseline_v1"). Empty when the policy
	// was hand-written without inheriting from a starter profile.
	// Bound into the receipt hash when present.
	ProfileTag string `json:"profile_tag,omitempty"`

	// RequiredFields is the full sorted list of attested fields the
	// policy required at admission. Carried so a verifier reading the
	// receipt can see the full required set, not just the missing
	// subset, without consulting the policy document separately.
	RequiredFields []string `json:"required_fields"`

	// Version is always "vfa.attestation_gap_receipt.v1" for this
	// artifact version.
	Version string `json:"version"`

	// Hash is the canonical SHA-256 hex of the preimage fields above.
	// Filled by BuildAttestationGapReceiptHash; this field is NOT part
	// of the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// ErrAttestationGapReceiptHashMismatch is returned when verification
// recomputes a receipt's hash and finds it disagrees with the stored
// Hash field — an indication of tampering or a software-version mismatch
// between the seal-time and verify-time canonicalizers.
var ErrAttestationGapReceiptHashMismatch = errors.New(
	"artifacts: attestation gap receipt hash mismatch",
)

// BuildAttestationGapReceiptHash computes the canonical hash of the
// receipt's preimage and populates the Hash field. The receipt argument
// is mutated in place; the resulting hash is also returned.
//
// Determinism: MissingFields and RequiredFields are sorted before
// hashing so callers passing unsorted slices still get a stable hash.
// This is defense-in-depth; the gap evaluator already sorts both lists,
// but a verifier replaying the receipt from JSON should not have to
// trust that property.
func BuildAttestationGapReceiptHash(receipt *AttestationGapReceipt) (string, error) {
	if receipt == nil {
		return "", errors.New("artifacts: nil AttestationGapReceipt")
	}
	missing := append([]string(nil), receipt.MissingFields...)
	sort.Strings(missing)
	required := append([]string(nil), receipt.RequiredFields...)
	sort.Strings(required)

	preimage := struct {
		DecisionReasonCode string   `json:"decision_reason_code"`
		EnvelopeID         string   `json:"envelope_id"`
		EvaluatorVersion   string   `json:"evaluator_version"`
		GapClock           string   `json:"gap_clock"`
		MissingFields      []string `json:"missing_fields"`
		PolicyHash         string   `json:"policy_hash"`
		PolicyID           string   `json:"policy_id"`
		PolicyName         string   `json:"policy_name"`
		ProfileTag         string   `json:"profile_tag,omitempty"`
		RequiredFields     []string `json:"required_fields"`
		Version            string   `json:"version"`
	}{
		DecisionReasonCode: receipt.DecisionReasonCode,
		EnvelopeID:         receipt.EnvelopeID,
		EvaluatorVersion:   receipt.EvaluatorVersion,
		GapClock:           receipt.GapClock,
		MissingFields:      missing,
		PolicyHash:         receipt.PolicyHash,
		PolicyID:           receipt.PolicyID,
		PolicyName:         receipt.PolicyName,
		ProfileTag:         receipt.ProfileTag,
		RequiredFields:     required,
		Version:            receipt.Version,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	receipt.Hash = hash
	receipt.MissingFields = missing
	receipt.RequiredFields = required
	return hash, nil
}

// VerifyAttestationGapReceiptHash recomputes the receipt's canonical
// hash from its preimage fields and compares to the stored Hash field.
// Returns nil on match, ErrAttestationGapReceiptHashMismatch otherwise.
//
// This is what the standalone verdifax-verify CLI calls to validate
// independently-submitted AttestationGapReceipts.
func VerifyAttestationGapReceiptHash(receipt *AttestationGapReceipt) error {
	if receipt == nil {
		return errors.New("artifacts: nil AttestationGapReceipt")
	}
	expected := receipt.Hash
	receipt.Hash = ""
	defer func() { receipt.Hash = expected }()
	actual, err := BuildAttestationGapReceiptHash(receipt)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrAttestationGapReceiptHashMismatch
	}
	return nil
}

// HumanSummary returns a one-paragraph buyer-readable explanation of
// the gap, suitable for sidecar display next to the sealed receipt.
// NOT bound into the receipt hash — purely an advisory rendering
// helper. The PDF and verify page may compose richer text on top of
// this; they all share this baseline summary.
func (r *AttestationGapReceipt) HumanSummary() string {
	if r == nil || len(r.MissingFields) == 0 {
		return "Attestation complete; no gap recorded."
	}
	prefix := "Admission halted: the active policy"
	if r.ProfileTag != "" {
		prefix += " (" + r.ProfileTag + ")"
	}
	prefix += " requires the caller to declare "
	if len(r.MissingFields) == 1 {
		return prefix + r.MissingFields[0] +
			", which was not present in the submitted attested context."
	}
	joined := r.MissingFields[0]
	for i := 1; i < len(r.MissingFields); i++ {
		if i == len(r.MissingFields)-1 {
			joined += " and " + r.MissingFields[i]
		} else {
			joined += ", " + r.MissingFields[i]
		}
	}
	return prefix + joined +
		", none of which were present in the submitted attested context."
}

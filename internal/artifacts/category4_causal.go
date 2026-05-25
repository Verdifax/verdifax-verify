package artifacts

// Category 4, Causal Graph
//
// Records what this run is causally connected to: parent runs that
// triggered it, related runs in the same workflow, the entities the
// decision was *about*, the downstream effects the decision triggered,
// and signal-level metadata (model confidence, out-of-distribution
// flags, adversarial signals).
//
// This is what makes Verdifax a graph rather than a list of isolated
// records. Auditors trace causality by walking these edges; risk teams
// detect anomalies by comparing across edges.

// CausalGraph captures the full relational context of a run.
type CausalGraph struct {
	Kind string `json:"kind"` // "verdifax.causal_graph.v1"

	// ParentRunID, the run that caused this one to fire.
	ParentRunID int64 `json:"parent_run_id,omitempty"`

	// RelatedRunIDs, sibling runs in a multi-step workflow.
	RelatedRunIDs []int64 `json:"related_run_ids,omitempty"`

	// AffectedEntities, what is this decision *about*? Each entity is
	// recorded as a kind plus a hash of its identifier (raw IDs would
	// leak PII; auditors can match entity hashes when cross-referencing
	// against their own records using the same hash function).
	AffectedEntities []EntityRef `json:"affected_entities,omitempty"`

	// EffectLog, what downstream actions did this decision trigger?
	// Webhook receipts, payment instructions, file changes, message
	// sends. Each effect carries an acknowledgement hash so the chain
	// of effect is verifiable.
	EffectLog []EffectEntry `json:"effect_log,omitempty"`

	// ConfidenceScore, caller-attested model confidence (0..1) for
	// this decision. Below-threshold values may indicate the run
	// should have been escalated for human review.
	ConfidenceScore *float64 `json:"confidence_score,omitempty"`

	// OutOfDistribution, did the input fall outside the model's
	// training distribution? Caller-attested boolean.
	OutOfDistribution *bool `json:"out_of_distribution,omitempty"`

	// AdversarialSignals, any indicators of adversarial input.
	// Examples (non-exhaustive):
	//   "prompt_injection_detected"
	//   "jailbreak_attempt_detected"
	//   "off_policy_request"
	//   "encoding_attack_detected"
	//   "context_overflow"
	//   "tool_misuse_detected"
	//   "exfiltration_attempt"
	AdversarialSignals []string `json:"adversarial_signals,omitempty"`

	// CohortPercentile, caller-attested percentile of this decision
	// vs. similar decisions in a defined window (0..1). 0.95 means
	// "this is in the 95th percentile", outlier detection lives here.
	CohortPercentile *float64 `json:"cohort_percentile,omitempty"`

	// CohortWindow, the cohort the percentile is measured against
	// (e.g. "last_24h", "last_7d_same_program", "lifetime").
	CohortWindow string `json:"cohort_window,omitempty"`

	Hash string        `json:"hash"`
	Seal SealReference `json:"seal,omitempty"`
}

// EntityRef, one entity affected by this decision.
type EntityRef struct {
	Kind        string `json:"kind"` // "customer" | "transaction" | "claim" | "patient" | "case" | "account" | "policy"
	IDHash      string `json:"id_hash"`         // sha256 of the entity's natural ID
	IDInline    string `json:"id_inline,omitempty"` // opt-in raw ID; off by default
	Description string `json:"description,omitempty"`
	JurisdictionCountry string `json:"jurisdiction_country,omitempty"` // for cross-border decisions
}

// EffectEntry, one downstream action triggered by this decision.
type EffectEntry struct {
	EffectKind     string `json:"effect_kind"` // "webhook" | "ledger_entry" | "payment_instruction" | "message" | "ticket" | "case_creation" | "data_write"
	Target         string `json:"target,omitempty"`         // e.g. "https://bank.example/webhook" or "ledger:txn_3334"
	Status         string `json:"status"`                  // "queued" | "sent" | "confirmed" | "failed" | "retrying"
	IssuedAt       string `json:"issued_at,omitempty"`     // RFC3339
	AcknowledgedAt string `json:"acknowledged_at,omitempty"`
	AckHash        string `json:"ack_hash,omitempty"`      // hash of the acknowledgement / receipt
	ErrorReason    string `json:"error_reason,omitempty"`  // when status == "failed"
}

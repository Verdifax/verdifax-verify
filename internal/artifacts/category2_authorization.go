package artifacts

// Category 2 — Authorization Chain
//
// Records the full authorization story for the run: who approved (possibly
// multiple people), what thresholds were checked, whether human review
// was required and performed, what the risk score was, and whether
// segregation-of-duties constraints were satisfied.
//
// Every field is caller-attested. Verdifax does not run an authorization
// engine itself; it records the caller's evidence that authorization was
// performed.

// AuthorizationChain captures the full multi-layer authorization picture.
type AuthorizationChain struct {
	Kind string `json:"kind"` // "verdifax.authorization_chain.v1"

	// Approvers — every party that signed off on this decision, in order.
	// For single-actor decisions this is empty (the actor in
	// AttestedContext is the sole approver).
	Approvers []Approver `json:"approvers,omitempty"`

	// ThresholdChecks — every dollar / risk / volume threshold that was
	// evaluated, with the observed value and whether it breached.
	ThresholdChecks []ThresholdCheck `json:"threshold_checks,omitempty"`

	// HumanInLoop — was human review required by policy, and was it done?
	HumanInLoop HITLStatus `json:"human_in_loop,omitempty"`

	// Risk — what risk class did the caller assign to this decision?
	Risk *RiskAssessment `json:"risk,omitempty"`

	// SegregationOfDuties — did the actor have authority to both
	// initiate and approve this kind of decision? Bank auditors care.
	SegregationOfDuties SegregationStatus `json:"segregation_of_duties,omitempty"`

	// Delegation — if the actor was acting on behalf of someone else,
	// the chain of delegation.
	Delegation []DelegationRef `json:"delegation,omitempty"`

	Hash string        `json:"hash"`
	Seal SealReference `json:"seal,omitempty"`
}

// Approver represents one signature in a multi-step approval chain.
type Approver struct {
	Order              int    `json:"order"`                   // 1, 2, 3 ...
	ActorID            string `json:"actor_id"`
	ActorRole          string `json:"actor_role,omitempty"`
	ApprovedAt         string `json:"approved_at"`             // RFC3339
	ApprovedRequestHash string `json:"approved_request_hash"`  // hash of the request as the approver saw it
	Signature          string `json:"signature,omitempty"`     // base64 or detached signature reference
	SignatureKind      string `json:"signature_kind,omitempty"` // "ed25519" | "rsa-pss-sha256" | "external"
	Comment            string `json:"comment,omitempty"`       // free-form
}

// ThresholdCheck records one quantitative limit evaluation.
type ThresholdCheck struct {
	Name              string  `json:"name"`               // e.g. "transaction_amount_usd"
	ThresholdValue    float64 `json:"threshold_value"`    // e.g. 100000
	ObservedValue     float64 `json:"observed_value"`     // e.g. 250000
	Unit              string  `json:"unit,omitempty"`     // "USD" | "count" | "percentage"
	Operator          string  `json:"operator"`           // ">", ">=", "<", "<=", "==", "!="
	Breached          bool    `json:"breached"`           // true if the operator+threshold+observed condition fired
	PolicyTriggered   string  `json:"policy_triggered,omitempty"` // policy id that the breach activated
}

// HITLStatus — Human-In-The-Loop status.
type HITLStatus struct {
	Required        bool   `json:"required"`
	Performed       bool   `json:"performed"`
	PerformedBy     string `json:"performed_by,omitempty"`     // actor id
	PerformedAt     string `json:"performed_at,omitempty"`     // RFC3339
	ReviewMode      string `json:"review_mode,omitempty"`      // "blocking" | "advisory" | "post_facto"
	ReviewOutcome   string `json:"review_outcome,omitempty"`   // "approved" | "rejected" | "modified"
	ModificationsHash string `json:"modifications_hash,omitempty"` // if reviewer changed anything
}

// RiskAssessment — caller-attested risk classification.
type RiskAssessment struct {
	Score          float64 `json:"score"`                // 0..1
	Class          string  `json:"class"`                // "low" | "medium" | "high" | "critical"
	ScoringMethod string  `json:"scoring_method,omitempty"` // "internal_risk_engine_v3" | "manual"
	Factors        []string `json:"factors,omitempty"`   // ["high_amount", "new_counterparty", "off_hours"]
}

// SegregationStatus — was segregation-of-duties satisfied?
type SegregationStatus struct {
	Required  bool   `json:"required"`
	Satisfied bool   `json:"satisfied"`
	Note      string `json:"note,omitempty"`
}

// DelegationRef — if the actor was acting on behalf of someone else.
type DelegationRef struct {
	OnBehalfOf       string `json:"on_behalf_of"`       // delegator actor id
	DelegationGrant  string `json:"delegation_grant"`   // grant id / hash
	GrantExpiresAt   string `json:"grant_expires_at,omitempty"`
}

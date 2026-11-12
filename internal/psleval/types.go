// Package psleval decides which policy rule fires. It is the whole decision
// and nothing else: no hashing, no signing, no storage.
//
// The server decides with this package, and the public verifier repeats the
// decision with a byte-identical copy of this directory, so a reader does not
// have to trust the server to have applied the rules. Nothing here imports
// another package of either project, which is what lets the copy be exact.
package psleval

// Effect is either Allow or Deny.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule is one allow-or-deny rule. See spec section 3.
type Rule struct {
	RuleID             string      `json:"rule_id"`
	RuleName           string      `json:"rule_name,omitempty"` // excluded from policy_hash
	Effect             Effect      `json:"effect"`
	Subject            Subject     `json:"subject"`
	Verb               Verb        `json:"verb"`
	Object             Object      `json:"object"`
	Conditions         []Condition `json:"conditions,omitempty"`
	Priority           int         `json:"priority,omitempty"` // reserved; validation refuses a non-zero value
	ReasonCodeOverride string      `json:"reason_code,omitempty"`
	AIReview           *AIReview   `json:"ai_review,omitempty"` // allow rules only
	// SignOff is the rule's choice about a person's sign-off on the results
	// of the steps it allows (round 58, B7): a customer marks the rules for
	// its higher-risk decisions. Allow rules only.
	SignOff *SignOff `json:"signoff,omitempty"`
}

// SignOff is a rule's sign-off requirement. Required means a result the rule
// allowed counts as signed off only once an approver of the account has
// approved it; the run's answer is returned at once as for any other rule,
// and the requirement is sealed through the policy hash.
type SignOff struct {
	Required bool `json:"required,omitempty"`
}

// SignOffRequired reports whether the rule that allowed a step requires a
// person's sign-off on its result.
func SignOffRequired(fired *Rule) bool {
	return fired != nil && fired.SignOff != nil && fired.SignOff.Required
}

// ContradictionMode is what a contradiction the AI review finds in a step's
// answer does to the step: halt it, or record the finding and let it
// continue.
type ContradictionMode string

const (
	ContradictionHalt   ContradictionMode = "halt"
	ContradictionRecord ContradictionMode = "record"
)

// AIReview is a policy's choice about the AI review of the steps it allows:
// what a contradiction does, and whether every step it allows must carry an
// AI review (Required), so a step that declares no AI output is refused.
type AIReview struct {
	Contradiction ContradictionMode `json:"contradiction"`
	Required      bool              `json:"required,omitempty"`
}

// ReasonAIReviewRequired is the reason a step is refused when its policy
// requires an AI review and the request declared no AI output.
const ReasonAIReviewRequired = "ai_review_required"

// ReviewRequired reports whether a step the policy allowed must carry an AI
// review: when the policy requires it, or the fired rule does. A rule that
// sets only its contradiction choice never lifts the policy's requirement.
func ReviewRequired(fired *Rule, policyDefault *AIReview) bool {
	return (fired != nil && fired.AIReview != nil && fired.AIReview.Required) ||
		(policyDefault != nil && policyDefault.Required)
}

// KnownContradictionMode reports whether m is a mode the review applies.
func KnownContradictionMode(m ContradictionMode) bool {
	return m == ContradictionHalt || m == ContradictionRecord
}

// ContradictionModeFor is what a contradiction finding does on a step the
// policy allowed: the fired rule's choice, else the policy's own, else halt.
// A step allowed by the default effect has no fired rule; pass nil.
func ContradictionModeFor(fired *Rule, policyDefault *AIReview) ContradictionMode {
	if fired != nil && fired.AIReview != nil {
		return fired.AIReview.Contradiction
	}
	if policyDefault != nil {
		return policyDefault.Contradiction
	}
	return ContradictionHalt
}

// Subject describes who is making the request.
type Subject struct {
	Type      SubjectType `json:"type"`
	IDMatch   Matcher     `json:"id_match"`
	RoleMatch *Matcher    `json:"role_match,omitempty"`
}

// SubjectType is one of the documented subject categories.
type SubjectType string

const (
	SubjectTypeAgent   SubjectType = "agent"
	SubjectTypeUser    SubjectType = "user"
	SubjectTypeService SubjectType = "service"
	SubjectTypeSystem  SubjectType = "system"
	SubjectTypeAny     SubjectType = "any"
)

// Verb describes what the request is asking the system to do.
type Verb struct {
	Match Matcher `json:"match"`
}

// Object describes what the request is acting upon.
type Object struct {
	Type              ObjectType          `json:"type"`
	IDMatch           Matcher             `json:"id_match"`
	ClassificationMax ClassificationLevel `json:"classification_max,omitempty"`
	ClassificationMin ClassificationLevel `json:"classification_min,omitempty"`
}

// ObjectType is one of the documented object categories.
type ObjectType string

const (
	ObjectTypeText        ObjectType = "text"
	ObjectTypeTransaction ObjectType = "transaction"
	ObjectTypeCode        ObjectType = "code"
	ObjectTypeData        ObjectType = "data"
	ObjectTypeModel       ObjectType = "model"
	ObjectTypeFile        ObjectType = "file"
	ObjectTypeAny         ObjectType = "any"
)

// ClassificationLevel orders from least to most sensitive.
type ClassificationLevel string

const (
	ClassificationPublic       ClassificationLevel = "PUBLIC"
	ClassificationInternal     ClassificationLevel = "INTERNAL"
	ClassificationConfidential ClassificationLevel = "CONFIDENTIAL"
	ClassificationRestricted   ClassificationLevel = "RESTRICTED"
	ClassificationTopSecret    ClassificationLevel = "TOP_SECRET"
	ClassificationTSSCI        ClassificationLevel = "TS_SCI"
)

// Condition is an additional predicate a rule must meet. Only the fields of
// its Type are read.
type Condition struct {
	Type          ConditionType `json:"type"`
	MaxPerWindow  int           `json:"max_per_window,omitempty"`
	WindowSeconds int           `json:"window_seconds,omitempty"`
	StartUTC      string        `json:"start_utc,omitempty"`
	EndUTC        string        `json:"end_utc,omitempty"`
	Required      bool          `json:"required,omitempty"`
	Seconds       int           `json:"seconds,omitempty"`
	Role          string        `json:"role,omitempty"`
	// MaxAgeSeconds and Checks belong to a data_quality condition (round 58,
	// B9): the data's as_of at most this many seconds before the decision,
	// when set, and each named check declared with the result pass.
	MaxAgeSeconds int      `json:"max_age_seconds,omitempty"`
	Checks        []string `json:"checks,omitempty"`
}

// ConditionType is one of the documented condition kinds.
type ConditionType string

const (
	ConditionRateLimit     ConditionType = "rate_limit"
	ConditionTimeWindow    ConditionType = "time_window"
	ConditionMFARequired   ConditionType = "mfa_required"
	ConditionMinSessionAge ConditionType = "min_session_age"
	ConditionRequiresRole  ConditionType = "requires_role"
	// ConditionDataQuality holds when the request declared its data's
	// quality, with every check it names passing and, when max_age_seconds
	// is set, data no older than that at the decision (round 58, B9).
	ConditionDataQuality ConditionType = "data_quality"
)

// Matcher is the predicate used in subject, verb and object matching.
type Matcher struct {
	Operator MatchOperator `json:"operator"`
	Value    string        `json:"value,omitempty"`  // for exact, prefix, suffix, substring
	Values   []string      `json:"values,omitempty"` // for in, not_in
}

// MatchOperator is one of the documented operators.
type MatchOperator string

const (
	MatchAny       MatchOperator = "any"
	MatchExact     MatchOperator = "exact"
	MatchPrefix    MatchOperator = "prefix"
	MatchSuffix    MatchOperator = "suffix"
	MatchSubstring MatchOperator = "substring"
	MatchIn        MatchOperator = "in"
	MatchNotIn     MatchOperator = "not_in"
)

// The reason codes a decision can carry on its own.
const (
	ReasonRuleAllowed          = "RULE_ALLOWED"
	ReasonRuleDenied           = "RULE_DENIED"
	ReasonDefaultEffectApplied = "DEFAULT_EFFECT_APPLIED"
)

// DefaultRuleID names the outcome when no rule fired.
const DefaultRuleID = "default"

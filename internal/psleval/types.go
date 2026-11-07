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
}

// ConditionType is one of the documented condition kinds.
type ConditionType string

const (
	ConditionRateLimit     ConditionType = "rate_limit"
	ConditionTimeWindow    ConditionType = "time_window"
	ConditionMFARequired   ConditionType = "mfa_required"
	ConditionMinSessionAge ConditionType = "min_session_age"
	ConditionRequiresRole  ConditionType = "requires_role"
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

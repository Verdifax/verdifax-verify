package psleval

// EvaluationContext is what the rules are matched against.
type EvaluationContext struct {
	SubjectID         string
	SubjectType       SubjectType
	SubjectRole       string
	Verb              string
	ObjectType        ObjectType
	ObjectID          string
	Classification    ClassificationLevel
	MFASatisfied      bool
	SessionAgeSeconds int
	ClockEpoch        string
	EnvelopeID        string
	EnvelopeHash      string

	// RateCounts maps a rule_id with a rate_limit condition to the runs that
	// rule has admitted for this key inside its window.
	RateCounts map[string]int
}

// Inputs is every value a decision read, in the form sealed into a record or
// receipt. Given the policy and these values, a reader can reach the same
// decision without trusting the server that made it.
type Inputs struct {
	SubjectID         string              `json:"subject_id"`
	SubjectType       SubjectType         `json:"subject_type"`
	SubjectRole       string              `json:"subject_role,omitempty"`
	Verb              string              `json:"verb"`
	ObjectType        ObjectType          `json:"object_type"`
	ObjectID          string              `json:"object_id"`
	Classification    ClassificationLevel `json:"classification"`
	MFASatisfied      bool                `json:"mfa_satisfied,omitempty"`
	SessionAgeSeconds int                 `json:"session_age_seconds,omitempty"`
	EvaluatedAt       string              `json:"evaluated_at"`
	RateCounts        map[string]int      `json:"rate_counts,omitempty"`
}

// InputsOf reads the sealed form of a context.
func InputsOf(ctx *EvaluationContext) Inputs {
	return Inputs{
		SubjectID: ctx.SubjectID, SubjectType: ctx.SubjectType, SubjectRole: ctx.SubjectRole,
		Verb: ctx.Verb, ObjectType: ctx.ObjectType, ObjectID: ctx.ObjectID,
		Classification: ctx.Classification, MFASatisfied: ctx.MFASatisfied,
		SessionAgeSeconds: ctx.SessionAgeSeconds, EvaluatedAt: ctx.ClockEpoch,
		RateCounts: ctx.RateCounts,
	}
}

// Context rebuilds the context the inputs came from. The envelope fields stay
// empty: they bind the evaluation hash, not the decision.
func (in Inputs) Context() *EvaluationContext {
	return &EvaluationContext{
		SubjectID: in.SubjectID, SubjectType: in.SubjectType, SubjectRole: in.SubjectRole,
		Verb: in.Verb, ObjectType: in.ObjectType, ObjectID: in.ObjectID,
		Classification: in.Classification, MFASatisfied: in.MFASatisfied,
		SessionAgeSeconds: in.SessionAgeSeconds, ClockEpoch: in.EvaluatedAt,
		RateCounts: in.RateCounts,
	}
}

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
	// AIOutputDeclared is whether the request declared an AI output for the
	// review. It is not one of the sealed inputs: every record and receipt
	// already seals the output's hash, empty when none was declared, and a
	// reader sets this from it.
	AIOutputDeclared bool

	// RateCounts maps a rule_id with a rate_limit condition to the runs that
	// rule has admitted for this key inside its window.
	RateCounts map[string]int

	// DataQuality is the request's own declaration about the data its
	// decision used (round 58, B9), nil when it made none.
	DataQuality *DataQuality
}

// DataQuality is a request's declaration about the data its decision used:
// where it came from, the time it describes, and the checks the customer ran
// on it, each with its result. Verdifax judges none of it; it seals what was
// declared, and a policy's data_quality condition can require and test it.
type DataQuality struct {
	Source string      `json:"source,omitempty"`
	AsOf   string      `json:"as_of,omitempty"`
	Checks []DataCheck `json:"checks,omitempty"`
}

// DataCheck is one named check the customer ran on the data, and its result:
// pass, fail or warn.
type DataCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

// DataCheckPass is the result a data_quality condition requires of a check
// it names.
const DataCheckPass = "pass"

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
	DataQuality       *DataQuality        `json:"data_quality,omitempty"`
}

// InputsOf reads the sealed form of a context.
func InputsOf(ctx *EvaluationContext) Inputs {
	return Inputs{
		SubjectID: ctx.SubjectID, SubjectType: ctx.SubjectType, SubjectRole: ctx.SubjectRole,
		Verb: ctx.Verb, ObjectType: ctx.ObjectType, ObjectID: ctx.ObjectID,
		Classification: ctx.Classification, MFASatisfied: ctx.MFASatisfied,
		SessionAgeSeconds: ctx.SessionAgeSeconds, EvaluatedAt: ctx.ClockEpoch,
		RateCounts: ctx.RateCounts, DataQuality: ctx.DataQuality,
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
		RateCounts: in.RateCounts, DataQuality: in.DataQuality,
	}
}

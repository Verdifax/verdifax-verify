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

	// Setup is the setup facts of the run, each labelled by who stated it
	// (round 64, setup change), nil when none is sealed.
	Setup *Setup
	// DataUse is the request's own declaration of the data use its decision
	// rests on (round 64, data-use basis), nil when it made none.
	DataUse *DataUse
}

// Setup is the setup facts a decision read, grouped by who stated them: the
// caller declared some, and Verdifax's AI review states the others. Neither
// group is confirmed by the other; each is sealed as stated.
type Setup struct {
	DeclaredByCaller   *DeclaredSetup `json:"declared_by_caller,omitempty"`
	AttestedByVerdifax *AttestedSetup `json:"attested_by_verdifax,omitempty"`
}

// DeclaredSetup is what the caller declared about its AI setup. Model
// temperature is the text encoding/json writes for the declared number, such
// as 0.2, so a policy can match it as text.
type DeclaredSetup struct {
	ModelProvider    string `json:"model_provider,omitempty"`
	ModelName        string `json:"model_name,omitempty"`
	ModelVersion     string `json:"model_version,omitempty"`
	ModelTemperature string `json:"model_temperature,omitempty"`
	PromptHash       string `json:"prompt_hash,omitempty"`
	// ClientName and ClientVersion are the AI assistant's own declared name
	// and version, as an MCP client gives them: declared, not verified.
	ClientName    string `json:"client_name,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

// AttestedSetup is what Verdifax's own AI review states about itself: the
// model its response named, its review instruction and its checker.
type AttestedSetup struct {
	ReviewModel     string `json:"review_model,omitempty"`
	ReviewPromptID  string `json:"review_prompt_id,omitempty"`
	ReviewCheckerID string `json:"review_checker_id,omitempty"`
}

// The setup facts a policy can name, in a fixed order, and who states each.
const (
	SetupDeclaredByCaller   = "declared_by_caller"
	SetupAttestedByVerdifax = "attested_by_verdifax"
)

// SetupFacts lists every setup fact by its sealed name, in a fixed order.
var SetupFacts = []string{"model_provider", "model_name", "model_version", "model_temperature", "prompt_hash",
	"client_name", "client_version", "review_model", "review_prompt_id", "review_checker_id"}

// SetupFactSource is who states a setup fact, or "" for a name that is not
// one.
func SetupFactSource(fact string) string {
	switch fact {
	case "model_provider", "model_name", "model_version", "model_temperature", "prompt_hash", "client_name", "client_version":
		return SetupDeclaredByCaller
	case "review_model", "review_prompt_id", "review_checker_id":
		return SetupAttestedByVerdifax
	}
	return ""
}

// Fact returns the value of a setup fact and whether it was stated.
func (s *Setup) Fact(fact string) (string, bool) {
	if s == nil {
		return "", false
	}
	var value string
	if d := s.DeclaredByCaller; d != nil {
		switch fact {
		case "model_provider":
			value = d.ModelProvider
		case "model_name":
			value = d.ModelName
		case "model_version":
			value = d.ModelVersion
		case "model_temperature":
			value = d.ModelTemperature
		case "prompt_hash":
			value = d.PromptHash
		case "client_name":
			value = d.ClientName
		case "client_version":
			value = d.ClientVersion
		}
	}
	if a := s.AttestedByVerdifax; a != nil {
		switch fact {
		case "review_model":
			value = a.ReviewModel
		case "review_prompt_id":
			value = a.ReviewPromptID
		case "review_checker_id":
			value = a.ReviewCheckerID
		}
	}
	return value, value != ""
}

// DataUse is a request's declaration of the data use its decision rests on:
// the customer's own codes for the purpose, the basis and the categories of
// data, and an optional reference the customer computed itself as
// hmac-sha256:<64 hex>, so Verdifax never receives the real reference.
// Verdifax judges none of it; it seals the declaration as made.
type DataUse struct {
	Purpose    string   `json:"purpose,omitempty"`
	Basis      string   `json:"basis,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Reference  string   `json:"reference,omitempty"`
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
	// Setup and DataUse are absent unless sealed (round 64), so every record
	// and receipt sealed without them reads and hashes as before.
	Setup   *Setup   `json:"setup,omitempty"`
	DataUse *DataUse `json:"data_use,omitempty"`
}

// InputsOf reads the sealed form of a context.
func InputsOf(ctx *EvaluationContext) Inputs {
	return Inputs{
		SubjectID: ctx.SubjectID, SubjectType: ctx.SubjectType, SubjectRole: ctx.SubjectRole,
		Verb: ctx.Verb, ObjectType: ctx.ObjectType, ObjectID: ctx.ObjectID,
		Classification: ctx.Classification, MFASatisfied: ctx.MFASatisfied,
		SessionAgeSeconds: ctx.SessionAgeSeconds, EvaluatedAt: ctx.ClockEpoch,
		RateCounts: ctx.RateCounts, DataQuality: ctx.DataQuality,
		Setup: ctx.Setup, DataUse: ctx.DataUse,
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
		Setup: in.Setup, DataUse: in.DataUse,
	}
}

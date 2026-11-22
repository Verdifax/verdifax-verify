package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
)

// Who wrote the policy a run was decided under. A customer's policy must
// never read as Verdifax's approval, so every decision names its source.
const (
	PolicySourceCustomer = "customer"
	PolicySourceVerdifax = "verdifax"
)

// PolicyInputs is every value a policy decision read. With the policy
// document and these values, a reader can run the rules again without
// trusting the server that decided. All but EvaluatedAt and RateCounts
// are the customer's own statements.
type PolicyInputs struct {
	SubjectID         string         `json:"subject_id"`
	SubjectType       string         `json:"subject_type"`
	SubjectRole       string         `json:"subject_role,omitempty"`
	Verb              string         `json:"verb"`
	ObjectType        string         `json:"object_type"`
	ObjectID          string         `json:"object_id"`
	Classification    string         `json:"classification"`
	MFASatisfied      bool           `json:"mfa_satisfied,omitempty"`
	SessionAgeSeconds int            `json:"session_age_seconds,omitempty"`
	EvaluatedAt       string         `json:"evaluated_at"`
	RateCounts        map[string]int `json:"rate_counts,omitempty"`
	// DataQuality is the request's declaration about the data its decision
	// used (round 58, B9): the customer's own statement, sealed as given.
	DataQuality *DataQuality `json:"data_quality,omitempty"`
	// Setup is the run's setup facts, each labelled by who stated it, and
	// DataUse the request's declaration of its data use (round 64). Each is
	// absent unless sealed, so every record and receipt sealed without them
	// hashes as before.
	Setup   *SetupFacts `json:"setup,omitempty"`
	DataUse *DataUse    `json:"data_use,omitempty"`
}

// SetupFacts is psleval.Setup's sealed form: the setup facts grouped by who
// stated them. A test holds the two in step.
type SetupFacts struct {
	DeclaredByCaller   *DeclaredSetup `json:"declared_by_caller,omitempty"`
	AttestedByVerdifax *AttestedSetup `json:"attested_by_verdifax,omitempty"`
}

// DeclaredSetup is what the caller declared about its AI setup, the AI
// assistant's declared name and version among it: declared, not verified.
type DeclaredSetup struct {
	ModelProvider    string `json:"model_provider,omitempty"`
	ModelName        string `json:"model_name,omitempty"`
	ModelVersion     string `json:"model_version,omitempty"`
	ModelTemperature string `json:"model_temperature,omitempty"`
	PromptHash       string `json:"prompt_hash,omitempty"`
	ClientName       string `json:"client_name,omitempty"`
	ClientVersion    string `json:"client_version,omitempty"`
}

// AttestedSetup is what Verdifax's AI review states about itself.
type AttestedSetup struct {
	ReviewModel     string `json:"review_model,omitempty"`
	ReviewPromptID  string `json:"review_prompt_id,omitempty"`
	ReviewCheckerID string `json:"review_checker_id,omitempty"`
}

// DataUse is psleval.DataUse's sealed form: the customer's own codes for the
// purpose, basis and categories of data, and an optional reference it keyed
// itself. Verdifax seals the declaration as made.
type DataUse struct {
	Purpose    string   `json:"purpose,omitempty"`
	Basis      string   `json:"basis,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Reference  string   `json:"reference,omitempty"`
}

// DataQuality is a request's declaration about its data: where it came
// from, the time it describes, and the checks the customer ran on it. It is
// psleval.DataQuality's sealed form; a test holds the two in step.
type DataQuality struct {
	Source string      `json:"source,omitempty"`
	AsOf   string      `json:"as_of,omitempty"`
	Checks []DataCheck `json:"checks,omitempty"`
}

// DataCheck is one named check and its result: pass, fail or warn.
type DataCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

// PolicyBinding is the policy decision a refused or halted run seals in
// its receipt_context, so a receipt names the rules as a record does.
type PolicyBinding struct {
	Source         string        `json:"source"`
	PolicyHash     string        `json:"policy_hash"`
	DocumentHash   string        `json:"document_hash,omitempty"`
	ActivationHash string        `json:"activation_hash,omitempty"`
	Outcome        string        `json:"outcome"`
	FiredRuleID    string        `json:"fired_rule_id"`
	Inputs         *PolicyInputs `json:"inputs,omitempty"`
}

// fields lists the binding for the receipt context hash, labeled as the
// key's own policy.
func (b *PolicyBinding) fields() []string { return b.labeledFields("policy") }

// labeledFields lists the binding under a label, so the key's policy and the
// account's can never be read as each other. The inputs go in as one digest
// of their JSON, because their values are free text and a joined list could
// not keep them apart.
func (b *PolicyBinding) labeledFields(label string) []string {
	inputs := ""
	if b.Inputs != nil {
		encoded, encodeErr := json.Marshal(b.Inputs)
		if encodeErr == nil {
			sum := sha256.Sum256(encoded)
			inputs = hex.EncodeToString(sum[:])
		}
	}
	return []string{label, b.Source, b.PolicyHash, b.DocumentHash, b.ActivationHash, b.Outcome, b.FiredRuleID, inputs}
}

// ErrDataUseCopiesDiffer means a record or receipt would seal two different
// data-use declarations: its own field and a policy gate's inputs must hold
// one value, the one the request declared (round 64, the copy group).
var ErrDataUseCopiesDiffer = errors.New("the data-use declaration sealed in the policy inputs differs from the one in its own field")

// dataUseCopiesAgree checks every policy inputs copy of a data-use
// declaration against the record's own field. Inputs that seal none agree
// only when the own field is absent too, unless they are nil (no decision
// was made, as when a run stopped before the rules ran).
func dataUseCopiesAgree(own *DataUse, inputs ...*PolicyInputs) error {
	for _, in := range inputs {
		if in == nil {
			continue
		}
		if !reflect.DeepEqual(in.DataUse, own) {
			return ErrDataUseCopiesDiffer
		}
	}
	return nil
}

// DataUseCopiesAgree checks an allowed run's EPA section: its own data-use
// field and each policy gate's sealed inputs hold one value.
func (e *EPA) DataUseCopiesAgree() error {
	var inputs []*PolicyInputs
	for _, g := range []*PolicyGate{e.PolicyGate, e.AccountPolicyGate} {
		if g != nil {
			inputs = append(inputs, g.Inputs)
		}
	}
	return dataUseCopiesAgree(e.DataUse, inputs...)
}

// DataUseCopiesAgree checks a receipt context: its own data-use field and
// each policy binding's sealed inputs hold one value.
func (c *ReceiptContext) DataUseCopiesAgree() error {
	var inputs []*PolicyInputs
	for _, b := range []*PolicyBinding{c.Policy, c.AccountPolicy} {
		if b != nil {
			inputs = append(inputs, b.Inputs)
		}
	}
	return dataUseCopiesAgree(c.DataUse, inputs...)
}

// DataUseDigest is the SHA-256 of a data-use declaration's JSON, the form it
// joins a receipt context's hash in: its values are codes, but a digest keeps
// the joined list unambiguous, as the inputs digest does.
func DataUseDigest(du *DataUse) string {
	encoded, encodeErr := json.Marshal(du)
	if encodeErr != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

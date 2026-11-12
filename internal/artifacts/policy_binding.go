package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

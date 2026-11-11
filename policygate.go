package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
	"github.com/Verdifax/verdifax-verify/internal/pslbuiltin"
	"github.com/Verdifax/verdifax-verify/internal/psleval"
)

// PolicyGateCheck reports the policy decision a run seals, on an allowed run
// in its EPA section and on a refused or halted run in its receipt context,
// and, with --policy, what a policy document the reader holds shows about it.
//
// The values are covered by the record's or receipt's hashes and public-log
// entries, so editing them fails verification. What they cannot show on their
// own is that the rules were applied correctly: the record carries hashes, not
// the policy. --policy closes that. The document's hashes must equal the sealed
// ones, and where the run sealed the values the rules read, this tool runs the
// rules itself, with a copy of the server's decision code, and must reach the
// same rule and outcome. The sealed values are the customer's own statements,
// except the time and the rate count, which are the server's; a pass shows the
// rules were applied to those values, not that they were true.
type PolicyGateCheck struct {
	Present            bool   `json:"present"`
	PolicyID           string `json:"policy_id,omitempty"`
	PolicyName         string `json:"policy_name,omitempty"`
	PolicyVersion      string `json:"policy_version,omitempty"`
	PolicyHash         string `json:"policy_hash,omitempty"`
	FiredRuleID        string `json:"fired_rule_id,omitempty"`
	DecisionReasonCode string `json:"decision_reason_code,omitempty"`
	Source             string `json:"source,omitempty"`
	DocumentHash       string `json:"document_hash,omitempty"`
	ActivationHash     string `json:"activation_hash,omitempty"`
	Outcome            string `json:"outcome,omitempty"`
	DocumentChecked    bool   `json:"document_checked"`
	DocumentMatch      bool   `json:"document_match"`
	RulesChecked       bool   `json:"rules_checked"`
	// BuiltInFile names the Verdifax built-in policy this verifier carries
	// that the record is held to: by its sealed text hash on a record that
	// names Verdifax as the author, and by its policy hash on an earlier
	// record that names no author.
	BuiltInFile string `json:"builtin_file,omitempty"`
	Reason      string `json:"reason,omitempty"`

	inputs *artifacts.PolicyInputs
	// aiOutputDeclared is whether the record or receipt seals an AI
	// output's hash: a policy that requires an AI review refuses a step
	// without one, and the rules are run again with it (round 56).
	aiOutputDeclared bool
	identitySealed   bool
	// reviewCheck is how the rules' review requirement is held to this
	// decision when the rules are run again (round 57, N1): a completed
	// record ("record") must seal a review when the rule that allowed it
	// requires one, and a halt for a missing required review
	// ("review-required-halt") stands only when the rule requires one.
	// Empty for refusals, where no step ran.
	reviewCheck  string
	reviewSealed bool
}

// haltReasonReviewRequired is the AI review halt of a step whose policy
// requires a review when none was sealed (orchestrator, round 57, N1).
const haltReasonReviewRequired = "AIVP_T4_REVIEW_REQUIRED"

// policyGateOf reads the policy decision an allowed run seals.
func policyGateOf(b *artifacts.AuditBundle) PolicyGateCheck {
	c := policyGateOfRecord(b)
	c.aiOutputDeclared = b.AivpT4.AiOutputHash != ""
	c.reviewCheck, c.reviewSealed = "record", b.AivpT4.Review != nil
	return c
}

func policyGateOfRecord(b *artifacts.AuditBundle) PolicyGateCheck {
	if b.EPA.PolicyGate == nil {
		return PolicyGateCheck{Reason: "no policy gate sealed (record predates it, or the run had no policy gate)"}
	}
	return gateOf(b.EPA.PolicyGate)
}

// policyBindingOf reads the policy decision a refused or halted run seals. Its
// outcome and rule are what the policy's rules decided, which stays true when
// the built-in code scan then refused a run the rules allowed.
func policyBindingOf(b *artifacts.PolicyBinding) PolicyGateCheck {
	if b == nil {
		return PolicyGateCheck{Reason: "no policy decision sealed in this receipt"}
	}
	return PolicyGateCheck{
		Present:        true,
		PolicyHash:     b.PolicyHash,
		FiredRuleID:    b.FiredRuleID,
		Source:         b.Source,
		DocumentHash:   b.DocumentHash,
		ActivationHash: b.ActivationHash,
		Outcome:        b.Outcome,
		inputs:         b.Inputs,
	}
}

// checkBuiltIn holds a record to the Verdifax built-in policy it names. One
// naming Verdifax as the author must name, by the hash of its exact text, a
// version this verifier carries; that text is then checked as a --policy
// document would be, and the rules are run again on the sealed inputs. An
// earlier record that names no author is matched by its policy hash, so it
// reads as built-in only when it is. An author this verifier does not know
// fails, as an unknown field does.
func checkBuiltIn(c PolicyGateCheck) PolicyGateCheck {
	if !c.Present {
		return c
	}
	fail := func(format string, args ...any) PolicyGateCheck {
		c.DocumentChecked, c.DocumentMatch, c.Reason = true, false, fmt.Sprintf(format, args...)
		return c
	}
	switch c.Source {
	case artifacts.PolicySourceCustomer:
		return c
	case artifacts.PolicySourceVerdifax:
		if c.ActivationHash != "" {
			return fail("the record names Verdifax's built-in policy and also a customer's policy change record %s", safePrefix(c.ActivationHash))
		}
		published, found := pslbuiltin.ByDocumentHash(c.DocumentHash)
		if !found {
			return fail("the record names a Verdifax built-in policy with text hash %s, which this verifier release does not carry; use the latest release", safePrefix(c.DocumentHash))
		}
		c.BuiltInFile = published.File
		return checkPolicyDocument(c, published.Document)
	case "":
		if published, found := pslbuiltin.ByPolicyHash(c.PolicyHash); found {
			c.BuiltInFile = published.File
		}
		return c
	default:
		return fail("the record names policy author %q, which this verifier does not know", c.Source)
	}
}

// policyFailed reports a policy check that ran and did not hold.
func policyFailed(c PolicyGateCheck) bool { return c.DocumentChecked && !c.DocumentMatch }

// checkPolicyDocument compares a policy document with the sealed decision.
// Error model: every problem becomes the check's reason; this binary has no
// logger.
func checkPolicyDocument(c PolicyGateCheck, doc []byte) PolicyGateCheck {
	c.DocumentChecked = true
	if !c.Present {
		c.Reason = "--policy given, but this record seals no policy gate to compare it with"
		return c
	}
	got, docErr := policyhash.FromDocument(doc)
	if docErr != nil {
		c.Reason = fmt.Sprintf("the policy document could not be read as a policy: %v", docErr)
		return c
	}
	digest := sha256.Sum256(doc)
	switch documentHash := hex.EncodeToString(digest[:]); {
	case got.PolicyHash != c.PolicyHash:
		c.Reason = fmt.Sprintf("the document's policy hash %s is not the sealed %s", got.PolicyHash, c.PolicyHash)
		return c
	case c.identitySealed && (got.PolicyID != c.PolicyID || got.PolicyName != c.PolicyName || got.PolicyVersion != c.PolicyVersion):
		c.Reason = fmt.Sprintf("the document is %q %q version %q, the record names %q %q version %q",
			got.PolicyID, got.PolicyName, got.PolicyVersion, c.PolicyID, c.PolicyName, c.PolicyVersion)
		return c
	case c.DocumentHash != "" && documentHash != c.DocumentHash:
		c.Reason = fmt.Sprintf("the document's exact text hashes to %s, the record seals %s", documentHash, c.DocumentHash)
		return c
	}
	if c.inputs == nil {
		c.DocumentMatch = true
		return c
	}
	c.RulesChecked = true
	if ruleErr := rerunRules(c, doc); ruleErr != nil {
		c.Reason = ruleErr.Error()
		return c
	}
	c.DocumentMatch = true
	return c
}

// rerunRules decides again from the document and the sealed inputs.
func rerunRules(c PolicyGateCheck, doc []byte) error {
	rules, readErr := psleval.ReadDocument(doc)
	if readErr != nil {
		return fmt.Errorf("the rules could not be read: %w", readErr)
	}
	inputs, convertErr := sealedInputs(c.inputs)
	if convertErr != nil {
		return fmt.Errorf("the sealed inputs could not be read: %w", convertErr)
	}
	ctx := inputs.Context()
	ctx.AIOutputDeclared = c.aiOutputDeclared
	result, decideErr := psleval.DecideDocument(rules, ctx)
	if errors.Is(decideErr, psleval.ErrUnreadable) {
		return fmt.Errorf("the rules cannot be decided on the sealed inputs: %w", decideErr)
	}
	if decideErr != nil {
		return fmt.Errorf("the rules could not be run: %w", decideErr)
	}
	if result.FiredRuleID != c.FiredRuleID || string(result.Outcome) != c.Outcome {
		return fmt.Errorf("running the rules on the sealed inputs gives %s by rule %q, the record says %s by rule %q",
			result.Outcome, result.FiredRuleID, c.Outcome, c.FiredRuleID)
	}
	if result.Outcome != psleval.EffectAllow {
		return nil
	}
	var fired *psleval.Rule
	for i := range rules.Rules {
		if rules.Rules[i].RuleID == result.FiredRuleID {
			fired = &rules.Rules[i]
			break
		}
	}
	required := psleval.ReviewRequired(fired, rules.AIReview)
	switch {
	case c.reviewCheck == "record" && required && !c.reviewSealed:
		return fmt.Errorf("the policy requires an AI review on the steps rule %q allows, and the record seals none", result.FiredRuleID)
	case c.reviewCheck == "review-required-halt" && !required:
		return fmt.Errorf("the receipt says the step stopped because its policy requires an AI review, and rule %q requires none", result.FiredRuleID)
	}
	return nil
}

// sealedInputs turns the record's form of the inputs into the decision's. The
// two types are one field list, which a test holds in step.
func sealedInputs(in *artifacts.PolicyInputs) (psleval.Inputs, error) {
	var out psleval.Inputs
	encoded, encodeErr := json.Marshal(in)
	if encodeErr != nil {
		return out, encodeErr
	}
	return out, json.Unmarshal(encoded, &out)
}

// policyAuthor says who wrote the policy, so a customer's rules can never read
// as Verdifax's approval of them, and a policy reads as Verdifax's only when
// this verifier holds its text.
func policyAuthor(c PolicyGateCheck) string {
	switch {
	case c.Source == artifacts.PolicySourceCustomer:
		return "written by the customer; Verdifax did not write, review or approve it"
	case c.Source == artifacts.PolicySourceVerdifax && c.BuiltInFile != "":
		return "Verdifax's built-in policy, " + c.BuiltInFile + ", which this verifier carries"
	case c.Source == artifacts.PolicySourceVerdifax:
		return "names Verdifax's built-in policy, in a version this verifier does not carry"
	case c.Source == "" && c.BuiltInFile != "":
		return "not recorded in this record; its policy hash is Verdifax's built-in " + c.BuiltInFile
	case c.Source == "":
		return "not recorded in this record, and its policy hash is not a Verdifax built-in version"
	default:
		return fmt.Sprintf("unknown author %q", c.Source)
	}
}

// gateLabels are the words one policy decision is printed with.
type gateLabels struct {
	gate, author, document, flag, absent string
}

// printPolicyGate renders the policy gate line(s) of the human report.
func printPolicyGate(c PolicyGateCheck) {
	if !c.Present && !c.DocumentChecked {
		fmt.Printf("  Policy gate:      not sealed in this record (%s)\n", c.Reason)
		return
	}
	printGateLines(c, gateLabels{gate: "Policy gate:", author: "Policy author:", document: "Policy document:", flag: "--policy"})
}

// printGateLines renders one sealed decision and its document check.
func printGateLines(c PolicyGateCheck, l gateLabels) {
	line := func(label, format string, args ...any) {
		fmt.Printf("  %-18s%s\n", label, fmt.Sprintf(format, args...))
	}
	if c.Present {
		name := ""
		if c.identitySealed {
			name = fmt.Sprintf("%s %q version %s, ", c.PolicyID, c.PolicyName, c.PolicyVersion)
		}
		reason := ""
		if c.DecisionReasonCode != "" {
			reason = " (" + c.DecisionReasonCode + ")"
		}
		switch {
		case !c.identitySealed && c.Outcome == "" && c.FiredRuleID == "":
			line(l.gate, "%spolicy hash %s; its rules did not decide this run, which stopped before they ran", name, safePrefix(c.PolicyHash))
		case !c.identitySealed:
			line(l.gate, "%spolicy hash %s, rule %s%s, %s", name, safePrefix(c.PolicyHash), c.FiredRuleID, reason, c.Outcome)
		default:
			line(l.gate, "%spolicy hash %s, rule %s%s", name, safePrefix(c.PolicyHash), c.FiredRuleID, reason)
		}
		line(l.author, "%s", policyAuthor(c))
	}
	switch {
	case !c.DocumentChecked && c.BuiltInFile != "":
		line(l.document, "not checked; this record seals no author or inputs, so the rules cannot be run again")
	case !c.DocumentChecked:
		line(l.document, "not checked; pass %s FILE to confirm the named policy is the hashed one", l.flag)
	case !c.DocumentMatch:
		line(l.document, "✗ FAILED · %s", c.Reason)
	case c.RulesChecked:
		line(l.document, "matches, and the rules run on the sealed inputs reach the same rule and outcome")
		line("", "The inputs are what was declared; this does not show they were true")
	default:
		line(l.document, "matches: its recomputed hash and the sealed identity agree; this record seals no inputs, so the rules were not run")
	}
}

// applyPolicyDocument records the --policy check on the report; a
// document that does not match fails verification.
func applyPolicyDocument(r *Report, doc []byte) {
	r.PolicyGate = checkPolicyDocument(r.PolicyGate, doc)
	if policyFailed(r.PolicyGate) {
		r.AllPassed = false
		r.VerdictTier = "FAILED"
		r.RecordCoverage = "failed"
	}
}

// applyReceiptPolicyDocument is the same check for a refused or halted run.
func applyReceiptPolicyDocument(r *ReceiptReport, doc []byte) {
	r.PolicyGate = checkPolicyDocument(r.PolicyGate, doc)
	if policyFailed(r.PolicyGate) {
		r.VerdictTier, r.AllPassed, r.Reason = "FAILED", false, r.PolicyGate.Reason
	}
}

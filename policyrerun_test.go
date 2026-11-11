package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
	"github.com/Verdifax/verdifax-verify/internal/psleval"
)

const rerunPolicy = `{"schema":"psl.v1","policy_id":"acme-rules","policy_name":"Acme rules","policy_version":"3","effective_at":"2026-11-01T00:00:00Z","default_effect":"deny","rules":[
 {"rule_id":"no-restricted","effect":"deny","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"any","id_match":{"operator":"any"},"classification_min":"RESTRICTED"}},
 {"rule_id":"emails","effect":"allow","subject":{"type":"agent","id_match":{"operator":"any"}},"verb":{"match":{"operator":"exact","value":"tool.send_email"}},"object":{"type":"any","id_match":{"operator":"any"}},"conditions":[{"type":"rate_limit","max_per_window":2,"window_seconds":60}]}
]}`

func rerunInputs() *artifacts.PolicyInputs {
	return &artifacts.PolicyInputs{SubjectID: "agent-7", SubjectType: "agent", Verb: "tool.send_email", ObjectType: "data",
		ObjectID: "loans/42", Classification: "INTERNAL", EvaluatedAt: "2026-11-06T14:30:00Z", RateCounts: map[string]int{"emails": 1}}
}

// sealedCheck is what a customer's run seals for rerunPolicy.
func sealedCheck(t *testing.T) PolicyGateCheck {
	t.Helper()
	r, hashErr := policyhash.FromDocument([]byte(rerunPolicy))
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	sum := sha256.Sum256([]byte(rerunPolicy))
	return policyBindingOf(&artifacts.PolicyBinding{Source: artifacts.PolicySourceCustomer, PolicyHash: r.PolicyHash,
		DocumentHash: hex.EncodeToString(sum[:]), Outcome: "allow", FiredRuleID: "emails", Inputs: rerunInputs()})
}

func TestTheRulesRunAgainAndAgree(t *testing.T) {
	got := checkPolicyDocument(sealedCheck(t), []byte(rerunPolicy))
	if !got.DocumentMatch || !got.RulesChecked {
		t.Fatalf("%+v", got)
	}
}

// Each of these is a claim the rules do not support, or a value changed after
// the decision. The hashes of a forged record can be made to agree, so the
// rules themselves must catch it.
func TestARecordThatDisagreesWithItsRulesFails(t *testing.T) {
	for name, change := range map[string]func(*PolicyGateCheck){
		"another rule":          func(c *PolicyGateCheck) { c.FiredRuleID = "no-restricted" },
		"another outcome":       func(c *PolicyGateCheck) { c.Outcome = "deny" },
		"the default":           func(c *PolicyGateCheck) { c.FiredRuleID = "default" },
		"restricted data":       func(c *PolicyGateCheck) { c.inputs.Classification = "RESTRICTED" },
		"over the rate":         func(c *PolicyGateCheck) { c.inputs.RateCounts = map[string]int{"emails": 2} },
		"a different verb":      func(c *PolicyGateCheck) { c.inputs.Verb = "tool.delete" },
		"an unknown level":      func(c *PolicyGateCheck) { c.inputs.Classification = "SORT-OF" },
		"a changed document":    func(c *PolicyGateCheck) { c.DocumentHash = strings.Repeat("0", 64) },
		"a changed policy hash": func(c *PolicyGateCheck) { c.PolicyHash = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			c := sealedCheck(t)
			change(&c)
			if got := checkPolicyDocument(c, []byte(rerunPolicy)); got.DocumentMatch || got.Reason == "" {
				t.Fatalf("passed: %+v", got)
			}
		})
	}
}

// A policy the rules would decide differently must not pass by matching hashes.
func TestAnotherDocumentFailsEvenWithItsOwnHashes(t *testing.T) {
	other := strings.Replace(rerunPolicy, `"max_per_window":2`, `"max_per_window":1`, 1)
	r, hashErr := policyhash.FromDocument([]byte(other))
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	c := sealedCheck(t)
	c.PolicyHash = r.PolicyHash
	sum := sha256.Sum256([]byte(other))
	c.DocumentHash = hex.EncodeToString(sum[:])
	if got := checkPolicyDocument(c, []byte(other)); got.DocumentMatch {
		t.Fatalf("passed: %+v", got)
	}
}

// Two documents can share a policy hash, because metadata sits outside it. The
// exact text hash tells them apart.
func TestTheExactTextIsChecked(t *testing.T) {
	other := strings.Replace(rerunPolicy, `"effective_at"`, `"tags":["changed"],"effective_at"`, 1)
	r, hashErr := policyhash.FromDocument([]byte(other))
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	c := sealedCheck(t)
	if r.PolicyHash != c.PolicyHash {
		t.Fatal("tags now change the policy hash; this test needs another field")
	}
	if got := checkPolicyDocument(c, []byte(other)); got.DocumentMatch || !strings.Contains(got.Reason, "exact text") {
		t.Fatalf("%+v", got)
	}
}

// A record from before inputs were sealed still checks its hashes, and says the
// rules were not run.
func TestARecordWithNoInputsSaysTheRulesWereNotRun(t *testing.T) {
	c := sealedCheck(t)
	c.inputs, c.DocumentHash = nil, ""
	got := checkPolicyDocument(c, []byte(rerunPolicy))
	if !got.DocumentMatch || got.RulesChecked {
		t.Fatalf("%+v", got)
	}
}

func TestAReceiptWithNoPolicySealedFailsTheCheck(t *testing.T) {
	if got := checkPolicyDocument(policyBindingOf(nil), []byte(rerunPolicy)); got.DocumentMatch {
		t.Fatalf("%+v", got)
	}
}

func TestTheAuthorIsNamed(t *testing.T) {
	if got := policyAuthor(PolicyGateCheck{Source: artifacts.PolicySourceCustomer}); !strings.Contains(got, "did not write, review or approve") {
		t.Fatal(got)
	}
	for _, c := range []PolicyGateCheck{{Source: artifacts.PolicySourceVerdifax}, {}, {Source: "someone"},
		{Source: artifacts.PolicySourceVerdifax, BuiltInFile: "x.json"}, {BuiltInFile: "x.json"}} {
		if got := policyAuthor(c); strings.Contains(got, "written by the customer") {
			t.Fatalf("%+v reads as the customer's: %s", c, got)
		}
	}
}

// The record's inputs and the decision's inputs are one field list. A field
// missing from either would be dropped before the rules run again.
func TestTheInputTypesHoldTheSameFields(t *testing.T) {
	names := func(v any) []string {
		var out []string
		for i, typ := 0, reflect.TypeOf(v); i < typ.NumField(); i++ {
			out = append(out, typ.Field(i).Tag.Get("json"))
		}
		return out
	}
	if a, b := names(artifacts.PolicyInputs{}), names(psleval.Inputs{}); !reflect.DeepEqual(a, b) {
		t.Fatalf("%v\n%v", a, b)
	}
	in := rerunInputs()
	in.SubjectRole, in.MFASatisfied, in.SessionAgeSeconds = "analyst", true, 7
	out, convertErr := sealedInputs(in)
	if convertErr != nil {
		t.Fatal(convertErr)
	}
	back, _ := json.Marshal(out)
	want, _ := json.Marshal(in)
	if string(back) != string(want) {
		t.Fatalf("%s\n%s", back, want)
	}
}

// Round 56: a policy that requires an AI review refuses an allowed step that
// declared no AI output. The verifier runs the rules again with what the
// record or receipt seals about the AI output, so a refusal it records is
// reached again, and an allowed record with no AI output fails.
func TestARequiredReviewIsRunAgainFromTheSealedOutput(t *testing.T) {
	requiring := strings.Replace(rerunPolicy, `"rules":[`, `"ai_review":{"contradiction":"halt","required":true},"rules":[`, 1)
	r, hashErr := policyhash.FromDocument([]byte(requiring))
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	plain, _ := policyhash.FromDocument([]byte(rerunPolicy))
	if r.PolicyHash == plain.PolicyHash {
		t.Fatal("the requirement must change the policy hash")
	}
	// The server's psl.PolicyHash of the same document (orchestrator, round
	// 56), so the two hash implementations cannot drift apart.
	if want := "9443866aa7b3d22c396c2038fdbd3f3a25567c2024136663ce7851e30f921d68"; r.PolicyHash != want {
		t.Fatalf("the verifier hashes the requiring policy to %s, the server to %s", r.PolicyHash, want)
	}
	sum := sha256.Sum256([]byte(requiring))
	check := func(outcome, reason string, declared bool) PolicyGateCheck {
		c := policyBindingOf(&artifacts.PolicyBinding{Source: artifacts.PolicySourceCustomer, PolicyHash: r.PolicyHash,
			DocumentHash: hex.EncodeToString(sum[:]), Outcome: outcome, FiredRuleID: "emails", Inputs: rerunInputs()})
		c.aiOutputDeclared = declared
		return checkPolicyDocument(c, []byte(requiring))
	}
	if got := check("deny", "ai_review_required", false); !got.RulesChecked || got.Reason != "" {
		t.Fatalf("a refusal of a step with no AI output must be reached again: %+v", got)
	}
	if got := check("allow", "", false); got.RulesChecked && got.Reason == "" {
		t.Fatalf("an allowed step with no AI output under a policy that requires a review must fail: %+v", got)
	}
	if got := check("allow", "", true); !got.RulesChecked || got.Reason != "" {
		t.Fatalf("an allowed step with an AI output must pass: %+v", got)
	}
}

// Round 57, N1: a required review is satisfied only by a sealed review. A
// record the rule allowed must carry a review when the rule requires one, even
// when an answer was sent (a blank answer seals its hash and no review); and a
// halt that names a missing required review stands only when the rule
// requires one, so neither can be forged in the other direction.
func TestARequiredReviewMustBeSealedNotOnlyAnAnswer(t *testing.T) {
	requiring := strings.Replace(rerunPolicy, `"rules":[`, `"ai_review":{"contradiction":"halt","required":true},"rules":[`, 1)
	r, _ := policyhash.FromDocument([]byte(requiring))
	plainHash, _ := policyhash.FromDocument([]byte(rerunPolicy))
	check := func(doc string, hash, reviewCheck string, reviewSealed bool) PolicyGateCheck {
		sum := sha256.Sum256([]byte(doc))
		c := policyBindingOf(&artifacts.PolicyBinding{Source: artifacts.PolicySourceCustomer, PolicyHash: hash,
			DocumentHash: hex.EncodeToString(sum[:]), Outcome: "allow", FiredRuleID: "emails", Inputs: rerunInputs()})
		c.aiOutputDeclared = true
		c.reviewCheck, c.reviewSealed = reviewCheck, reviewSealed
		return checkPolicyDocument(c, []byte(doc))
	}
	if got := check(requiring, r.PolicyHash, "record", false); got.Reason == "" ||
		!strings.Contains(got.Reason, "requires an AI review") {
		t.Fatalf("a record with an answer but no sealed review under a required review must fail: %+v", got)
	}
	if got := check(requiring, r.PolicyHash, "record", true); got.Reason != "" {
		t.Fatalf("a record with a sealed review must pass: %+v", got)
	}
	if got := check(rerunPolicy, plainHash.PolicyHash, "record", false); got.Reason != "" {
		t.Fatalf("a record with no review under a rule that requires none must pass: %+v", got)
	}
	if got := check(requiring, r.PolicyHash, "review-required-halt", false); got.Reason != "" {
		t.Fatalf("a review-required halt under a rule that requires a review must pass: %+v", got)
	}
	if got := check(rerunPolicy, plainHash.PolicyHash, "review-required-halt", false); got.Reason == "" ||
		!strings.Contains(got.Reason, "requires none") {
		t.Fatalf("a review-required halt under a rule that requires none must fail: %+v", got)
	}
}

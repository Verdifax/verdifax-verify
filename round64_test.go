package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// round64Policy is a customer policy using both round 64 conditions: the
// allow rule names a fact the caller declares, a fact Verdifax's AI review
// states, and the data use it accepts.
const round64Policy = `{"schema":"psl.v1","policy_id":"r64-claims","policy_name":"R64 claims","policy_version":"1","effective_at":"2026-11-17T00:00:00Z","default_effect":"deny","rules":[{"rule_id":"reviewed-claims","effect":"allow","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"any","id_match":{"operator":"any"}},"conditions":[{"type":"attested_setup","facts":[{"fact":"model_name","match":{"operator":"in","values":["claims-model-2"]}},{"fact":"review_prompt_id","match":{"operator":"exact","value":"statements-v1"}}]},{"type":"data_use","purpose_match":{"operator":"exact","value":"claims.review"},"basis_match":{"operator":"in","values":["contract"]}}]}]}`

func round64Use() *artifacts.DataUse {
	return &artifacts.DataUse{Purpose: "claims.review", Basis: "contract", Categories: []string{"claims"}}
}

func round64Inputs() *artifacts.PolicyInputs {
	return &artifacts.PolicyInputs{SubjectID: "u-1", SubjectType: "user", Verb: "execute", ObjectType: "data", ObjectID: "claims/1",
		EvaluatedAt: "2026-11-17T12:00:00Z",
		Setup:       &artifacts.SetupFacts{DeclaredByCaller: &artifacts.DeclaredSetup{ModelName: "claims-model-2"}},
		DataUse:     round64Use()}
}

// round64Gate is an allowed run's sealed decision under round64Policy.
func round64Gate(t *testing.T) PolicyGateCheck {
	t.Helper()
	got, err := policyhash.FromDocument([]byte(round64Policy))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(round64Policy))
	return PolicyGateCheck{Present: true, PolicyHash: got.PolicyHash, FiredRuleID: "reviewed-claims", Source: artifacts.PolicySourceCustomer,
		DocumentHash: hex.EncodeToString(sum[:]), ActivationHash: strings.Repeat("a", 64), Outcome: "allow", inputs: round64Inputs(),
		reviewCheck: "record", reviewSealed: true, aiOutputDeclared: true,
		review: &artifacts.AivpReview{PromptID: "statements-v1", Model: "claude-opus-5-5", CheckerID: "keyword-v1"}}
}

// R311: the rules run again on a record's sealed setup facts and data use
// reach the sealed rule, and the report says what was declared and what the
// policy names; a changed declaration reaches another rule and fails.
func TestRound64ConditionsRunAgain(t *testing.T) {
	c := checkPolicyDocument(round64Gate(t), []byte(round64Policy))
	if !c.DocumentMatch || !c.RulesChecked {
		t.Fatalf("a record decided by the rules must match: %s", c.Reason)
	}
	want := []string{
		`model_name: the request declared "claims-model-2"; the policy names in [claims-model-2]`,
		`review_prompt_id: the AI review by Verdifax stated "statements-v1"; the policy names exact "statements-v1"`,
	}
	if strings.Join(c.SetupFacts, "|") != strings.Join(want, "|") {
		t.Fatalf("setup lines %q", c.SetupFacts)
	}
	for name, mutate := range map[string]func(g *PolicyGateCheck){
		"another basis":    func(g *PolicyGateCheck) { g.inputs.DataUse.Basis = "consent" },
		"no data use":      func(g *PolicyGateCheck) { g.inputs.DataUse = nil },
		"another model":    func(g *PolicyGateCheck) { g.inputs.Setup.DeclaredByCaller.ModelName = "claims-model-3" },
		"no setup":         func(g *PolicyGateCheck) { g.inputs.Setup = nil },
		"review mismatch":  func(g *PolicyGateCheck) { g.review.PromptID = "statements-v2" },
		"no review sealed": func(g *PolicyGateCheck) { g.review = nil },
	} {
		g := round64Gate(t)
		mutate(&g)
		if got := checkPolicyDocument(g, []byte(round64Policy)); got.DocumentMatch {
			t.Errorf("%s: the record still matches", name)
		}
	}
}

// R312: an AI review halt for the review's setup (AIVP_T4_REVIEW_SETUP)
// stands only when a rule that allowed the step names a review fact the
// sealed review did not meet.
func TestAReviewSetupHaltIsHeldToTheRules(t *testing.T) {
	halt := func(promptID string, rerun bool) *ReceiptReport {
		g := round64Gate(t)
		g.reviewCheck, g.reviewSealed = "review-setup-halt", false
		g.review.PromptID = promptID
		if rerun {
			g = checkPolicyDocument(g, []byte(round64Policy))
			if !g.DocumentMatch {
				t.Fatalf("the halt's decision must match: %s", g.Reason)
			}
		}
		r := &ReceiptReport{PolicyGate: g, AllPassed: true, VerdictTier: "VERIFIED_ANCHORED",
			reviewSetupHalt: &artifacts.AivpT4HaltReceipt{HaltReasonCode: haltReasonReviewSetup}}
		applyReviewSetupHalt(r)
		return r
	}
	if r := halt("statements-v2", true); !r.AllPassed || !strings.HasPrefix(r.ReviewSetupHalt, "confirmed") {
		t.Fatalf("a review that did not meet the rule confirms the halt: %+v", r)
	}
	if r := halt("statements-v1", true); r.AllPassed || r.VerdictTier != "FAILED" {
		t.Fatalf("a halt whose rule the review met must fail: %+v", r)
	}
	if r := halt("statements-v1", false); !r.AllPassed || !strings.HasPrefix(r.ReviewSetupHalt, "not confirmed") {
		t.Fatalf("without the rules run again the halt is not confirmed: %+v", r)
	}
}

func readRound59Bundle(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile("testdata/round59/run-3223-key-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := decodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// R313: a record's data-use copies are one value, every new sealed fact has
// the form the server seals, and the setup facts a decision sealed repeat the
// record's attested context; the report states the declarations as declared.
func TestRound64RecordFacts(t *testing.T) {
	if problems := round64BundleProblems(readRound59Bundle(t)); len(problems) != 0 {
		t.Fatalf("a record without round 64 facts: %v", problems)
	}
	if declaredOfBundle(readRound59Bundle(t)) != nil {
		t.Fatal("a record without round 64 facts reports nothing new")
	}
	good := func() *artifacts.AuditBundle {
		b := readRound59Bundle(t)
		b.EPA.DataUse = round64Use()
		b.EPA.PolicyGate.Inputs.DataUse = round64Use()
		b.EPA.AttestedContext.ModelName = "claims-model-2"
		b.EPA.AttestedContext.ClientName, b.EPA.AttestedContext.ClientVersion = "Claude Code", "2.1.0"
		b.EPA.PolicyGate.Inputs.Setup = &artifacts.SetupFacts{DeclaredByCaller: declaredSetupOf(b.EPA.AttestedContext)}
		return b
	}
	b := good()
	if problems := round64BundleProblems(b); len(problems) != 0 {
		t.Fatalf("a sound record: %v", problems)
	}
	d := declaredOfBundle(b)
	if d.DataUseStatement != "declared by the customer: purpose claims.review; basis contract; categories claims. Sealed as declared; Verdifax did not check it." {
		t.Fatalf("data use %q", d.DataUseStatement)
	}
	if d.ClientStatement != "Claude Code 2.1.0, declared by the AI assistant, not verified" {
		t.Fatalf("client %q", d.ClientStatement)
	}
	for name, mutate := range map[string]func(b *artifacts.AuditBundle){
		"copies differ":      func(b *artifacts.AuditBundle) { b.EPA.PolicyGate.Inputs.DataUse.Basis = "consent" },
		"inputs lack it":     func(b *artifacts.AuditBundle) { b.EPA.PolicyGate.Inputs.DataUse = nil },
		"own field lacks it": func(b *artifacts.AuditBundle) { b.EPA.DataUse = nil },
		"not a code": func(b *artifacts.AuditBundle) {
			b.EPA.DataUse.Purpose = "Claims Review"
			b.EPA.PolicyGate.Inputs.DataUse.Purpose = "Claims Review"
		},
		"plain reference": func(b *artifacts.AuditBundle) {
			b.EPA.DataUse.Reference = "contract-42"
			b.EPA.PolicyGate.Inputs.DataUse.Reference = "contract-42"
		},
		"client not ASCII": func(b *artifacts.AuditBundle) {
			b.EPA.AttestedContext.ClientName = "Claude Códe"
			b.EPA.PolicyGate.Inputs.Setup.DeclaredByCaller = declaredSetupOf(b.EPA.AttestedContext)
		},
		"setup copy differs": func(b *artifacts.AuditBundle) {
			b.EPA.PolicyGate.Inputs.Setup.DeclaredByCaller.ModelName = "claims-model-3"
		},
		"review facts in input": func(b *artifacts.AuditBundle) {
			b.EPA.PolicyGate.Inputs.Setup.AttestedByVerdifax = &artifacts.AttestedSetup{ReviewPromptID: "x"}
		},
	} {
		b := good()
		mutate(b)
		if len(round64BundleProblems(b)) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

// R313, receipts: the data-use copies, the setup fingerprint's form, and the
// policy change an attestation-gap receipt seals as the rule in force.
func TestRound64ReceiptFacts(t *testing.T) {
	ctx := func() *artifacts.ReceiptContext {
		return &artifacts.ReceiptContext{DataUse: round64Use(), SetupHash: strings.Repeat("e", 64),
			AccountPolicy: &artifacts.PolicyBinding{PolicyHash: strings.Repeat("4", 64), ActivationHash: strings.Repeat("a", 64)}}
	}
	if err := round64ReceiptProblem(ctx()); err != nil {
		t.Fatalf("a refusal before the rules ran carries the declaration alone: %v", err)
	}
	if d := declaredOfReceipt(ctx()); d == nil || d.SetupHash == "" || !strings.HasSuffix(d.DataUseStatement, "Verdifax did not check it.") {
		t.Fatalf("declared %+v", d)
	}
	for name, mutate := range map[string]func(c *artifacts.ReceiptContext){
		"copies differ": func(c *artifacts.ReceiptContext) {
			c.AccountPolicy.Inputs = &artifacts.PolicyInputs{DataUse: &artifacts.DataUse{Purpose: "claims.review", Basis: "consent"}}
		},
		"setup hash form": func(c *artifacts.ReceiptContext) { c.SetupHash = "E" },
		"review facts": func(c *artifacts.ReceiptContext) {
			c.AccountPolicy.Inputs = &artifacts.PolicyInputs{DataUse: round64Use(), Setup: &artifacts.SetupFacts{AttestedByVerdifax: &artifacts.AttestedSetup{ReviewModel: "m"}}}
		},
		"too many": func(c *artifacts.ReceiptContext) {
			c.DataUse.Categories = strings.Split("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u", ",")
		},
	} {
		c := ctx()
		mutate(c)
		if round64ReceiptProblem(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	gap := &artifacts.AttestationGapReceipt{PolicyHash: strings.Repeat("4", 64), ActivationHash: strings.Repeat("a", 64), GapClock: "2026-11-17T12:00:00Z"}
	if err := gapActivationProblem(gap, ctx()); err != nil {
		t.Fatalf("the context names the same change: %v", err)
	}
	other := *gap
	other.ActivationHash = strings.Repeat("b", 64)
	if gapActivationProblem(&other, ctx()) == nil {
		t.Fatal("a gap receipt naming a change its context does not name must fail")
	}
	if gapActivationOf(&artifacts.AttestationGapReceipt{PolicyHash: gap.PolicyHash}, ctx()) != gap.ActivationHash {
		t.Fatal("a receipt sealed before round 64 is matched by its context's change")
	}
}

// R314: a refusal for missing fields is matched to the change in force at its
// clock in the history given.
func TestTheRuleInForceIsTheChangeInForceAtTheGapClock(t *testing.T) {
	history := func() *PolicyHistoryCheck {
		return &PolicyHistoryCheck{OK: true, Entries: []PolicyHistoryEntry{
			{Sequence: 1, ChainID: "account-7", PolicyHash: strings.Repeat("4", 64), ActivatedAt: "2026-11-17T10:00:00Z", ActivationHash: strings.Repeat("a", 64)},
			{Sequence: 2, ChainID: "account-7", PolicyHash: strings.Repeat("5", 64), ActivatedAt: "2026-11-17T11:00:00Z", ActivationHash: strings.Repeat("b", 64)},
		}}
	}
	gap := &artifacts.AttestationGapReceipt{PolicyHash: strings.Repeat("4", 64), GapClock: "2026-11-17T10:30:00Z"}
	h := history()
	checkRuleInForce(h, gap, strings.Repeat("a", 64))
	if !h.OK || !strings.Contains(h.RuleInForce, "decided under change 1 of account-7") {
		t.Fatalf("in force: %+v", h)
	}
	// A refusal made after its change was replaced, naming the policy the
	// later change put in force, is caught by the change alone.
	late := *gap
	late.GapClock, late.PolicyHash = "2026-11-17T11:30:00Z", strings.Repeat("5", 64)
	h = history()
	checkRuleInForce(h, &late, strings.Repeat("a", 64))
	if h.OK {
		t.Fatal("a refusal made after its change was replaced must fail")
	}
	h = history()
	checkRuleInForce(h, &artifacts.AttestationGapReceipt{PolicyHash: strings.Repeat("6", 64), GapClock: gap.GapClock}, strings.Repeat("a", 64))
	if h.OK {
		t.Fatal("a refusal naming another policy than the change put in force must fail")
	}
}

// R315: the policy reader of every new key refuses a malformed one, and a
// document given with --signals-policy must be one this verifier reads.
func TestSignalsPolicyDocumentsAreRead(t *testing.T) {
	dir := t.TempDir()
	good, bad := dir+"/good.json", dir+"/bad.json"
	if err := os.WriteFile(good, []byte(round64Policy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(strings.Replace(round64Policy, `"default_effect":"deny",`, `"default_effect":"deny","review":{},`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	docs, err := readFeedPolicies(good)
	sum := sha256.Sum256([]byte(round64Policy))
	if err != nil || docs[hex.EncodeToString(sum[:])] == nil {
		t.Fatalf("documents %v %v", docs, err)
	}
	if _, err := readFeedPolicies(good + "," + bad); err == nil {
		t.Fatal("a malformed review declaration must be refused")
	}
}

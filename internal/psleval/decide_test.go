package psleval

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type sharedCase struct {
	Name          string `json:"name"`
	DefaultEffect Effect `json:"default_effect"`
	Rules         []Rule `json:"rules"`
	Inputs        Inputs `json:"inputs"`
	Unreadable    bool   `json:"unreadable"`
	Want          struct {
		Outcome     Effect `json:"outcome"`
		FiredRuleID string `json:"fired_rule_id"`
		ReasonCode  string `json:"reason_code"`
	} `json:"want"`
}

// This file and the cases are byte-identical in the server and the verifier,
// so each of them passes exactly the same list.
func TestSharedCases(t *testing.T) {
	raw, readErr := os.ReadFile("testdata/cases.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var cases []sharedCase
	if parseErr := json.Unmarshal(raw, &cases); parseErr != nil {
		t.Fatal(parseErr)
	}
	if len(cases) < 40 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got, decideErr := Decide(c.Rules, c.DefaultEffect, c.Inputs.Context())
			if c.Unreadable {
				if !errors.Is(decideErr, ErrUnreadable) {
					t.Fatalf("got %+v, %v, want ErrUnreadable", got, decideErr)
				}
				return
			}
			if decideErr != nil {
				t.Fatal(decideErr)
			}
			if got.Outcome != c.Want.Outcome || got.FiredRuleID != c.Want.FiredRuleID || got.ReasonCode != c.Want.ReasonCode {
				t.Fatalf("got %+v, want %+v", got, c.Want)
			}
		})
	}
}

func TestReadDocumentReadsTheRules(t *testing.T) {
	d, readErr := ReadDocument([]byte(`{"schema":"psl.v1","default_effect":"deny","rules":[{"rule_id":"r","effect":"allow"}]}`))
	if readErr != nil || d.DefaultEffect != EffectDeny || len(d.Rules) != 1 || d.Rules[0].RuleID != "r" {
		t.Fatalf("got %+v, %v", d, readErr)
	}
	if _, readErr = ReadDocument([]byte(`{`)); readErr == nil {
		t.Fatal("broken text was read")
	}
}

// A short or strange time must never crash a decision: the verifier reads
// these values from a record it does not trust.
func TestUnreadableTimesAreRefusedNotFatal(t *testing.T) {
	for _, clock := range []string{"", "x", "2026-11-06T14:30", "2026-11-06T1", "2026-13-40T99:99:99Z", "2026-11-06 14:30:00Z"} {
		if _, ok := minutesOfDay(clock); ok {
			t.Errorf("%q was read as a time", clock)
		}
	}
	for _, hhmm := range []string{"", "8:00", "24:00", "12:60", "ab:cd", "12-30", "12:3x"} {
		if _, ok := ParseHHMM(hhmm); ok {
			t.Errorf("%q was read as a time of day", hhmm)
		}
	}
}

// Every field of a context must survive sealing, or a reader would decide on
// less than the server did. The envelope fields bind the hash, not the decision.
func TestInputsCarryEveryField(t *testing.T) {
	ctx := EvaluationContext{SubjectID: "a", SubjectType: SubjectTypeAgent, SubjectRole: "b", Verb: "c", ObjectType: ObjectTypeData,
		ObjectID: "d", Classification: ClassificationInternal, MFASatisfied: true, SessionAgeSeconds: 5, ClockEpoch: "e",
		RateCounts:  map[string]int{"r": 1},
		DataQuality: &DataQuality{Source: "ledger", AsOf: "2026-11-11T00:00:00Z", Checks: []DataCheck{{Name: "complete", Result: DataCheckPass}}},
		Setup: &Setup{DeclaredByCaller: &DeclaredSetup{ModelName: "m", ClientName: "c"},
			AttestedByVerdifax: &AttestedSetup{ReviewPromptID: "statements-v1"}},
		DataUse: &DataUse{Purpose: "claims.review", Basis: "contract", Categories: []string{"claims"},
			Reference: "hmac-sha256:" + strings.Repeat("a", 64)}}
	v := reflect.ValueOf(ctx)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		// The envelope binds the evaluation hash only. AIOutputDeclared is
		// sealed already, as the record's and receipt's ai_output_hash; a
		// reader sets it from that, so the inputs carry no second copy.
		if name == "EnvelopeID" || name == "EnvelopeHash" || name == "AIOutputDeclared" {
			continue
		}
		if v.Field(i).IsZero() {
			t.Fatalf("set %s in this test", name)
		}
	}
	if got := InputsOf(&ctx).Context(); !reflect.DeepEqual(*got, ctx) {
		t.Fatalf("got %+v, want %+v", *got, ctx)
	}
}

// Round 56: a policy that requires an AI review refuses an allowed step that
// declared no AI output, through the policy or through the rule, and a rule
// that sets only its contradiction choice never lifts the policy's
// requirement. Every other decision is Decide's.
func TestDecideDocumentAppliesTheReviewRequirement(t *testing.T) {
	allowAll := Rule{RuleID: "steps", Effect: EffectAllow, Subject: Subject{Type: SubjectTypeAny, IDMatch: Matcher{Operator: "any"}},
		Verb: Verb{Match: Matcher{Operator: "any"}}, Object: Object{Type: ObjectTypeAny, IDMatch: Matcher{Operator: "any"}}}
	ctx := &EvaluationContext{SubjectID: "a", SubjectType: SubjectTypeAgent, Verb: "v", ObjectType: ObjectTypeData, ObjectID: "o",
		Classification: ClassificationInternal}
	contradictionOnly := allowAll
	contradictionOnly.AIReview = &AIReview{Contradiction: ContradictionRecord}
	requiringRule := allowAll
	requiringRule.AIReview = &AIReview{Contradiction: ContradictionHalt, Required: true}
	for name, c := range map[string]struct {
		doc      Document
		declared bool
		want     Effect
		reason   string
	}{
		"policy requires, none declared":       {Document{DefaultEffect: EffectDeny, Rules: []Rule{allowAll}, AIReview: &AIReview{Contradiction: ContradictionHalt, Required: true}}, false, EffectDeny, ReasonAIReviewRequired},
		"policy requires, declared":            {Document{DefaultEffect: EffectDeny, Rules: []Rule{allowAll}, AIReview: &AIReview{Contradiction: ContradictionHalt, Required: true}}, true, EffectAllow, ReasonRuleAllowed},
		"rule requires, none declared":         {Document{DefaultEffect: EffectDeny, Rules: []Rule{requiringRule}}, false, EffectDeny, ReasonAIReviewRequired},
		"rule sets only its contradiction":     {Document{DefaultEffect: EffectDeny, Rules: []Rule{contradictionOnly}, AIReview: &AIReview{Contradiction: ContradictionHalt, Required: true}}, false, EffectDeny, ReasonAIReviewRequired},
		"nothing required, none declared":      {Document{DefaultEffect: EffectDeny, Rules: []Rule{allowAll}}, false, EffectAllow, ReasonRuleAllowed},
		"default allow, policy requires, none": {Document{DefaultEffect: EffectAllow, AIReview: &AIReview{Contradiction: ContradictionHalt, Required: true}}, false, EffectDeny, ReasonAIReviewRequired},
	} {
		ctx.AIOutputDeclared = c.declared
		got, err := DecideDocument(c.doc, ctx)
		if err != nil || got.Outcome != c.want || got.ReasonCode != c.reason {
			t.Errorf("%s: got %+v %v, want %s %s", name, got, err, c.want, c.reason)
		}
	}
}

// Round 58, B9: a data_quality condition holds only for a declared data
// quality whose named checks all passed and, with max_age_seconds, whose
// as_of is no older than that at the decision and not after it.
func TestADataQualityConditionTestsTheDeclaration(t *testing.T) {
	clock := "2026-11-11T12:00:00Z"
	dq := func(asOf string, checks ...DataCheck) *DataQuality {
		return &DataQuality{Source: "core-ledger", AsOf: asOf, Checks: checks}
	}
	pass := func(name string) DataCheck { return DataCheck{Name: name, Result: DataCheckPass} }
	cond := Condition{Type: ConditionDataQuality, MaxAgeSeconds: 3600, Checks: []string{"complete", "schema"}}
	cases := []struct {
		name string
		data *DataQuality
		cond Condition
		want bool
	}{
		{"nothing declared", nil, Condition{Type: ConditionDataQuality}, false},
		{"declared, nothing required", dq(""), Condition{Type: ConditionDataQuality}, true},
		{"fresh, both checks passed", dq("2026-11-11T11:30:00Z", pass("complete"), pass("schema")), cond, true},
		{"a named check failed", dq("2026-11-11T11:30:00Z", pass("complete"), DataCheck{Name: "schema", Result: "fail"}), cond, false},
		{"a named check missing", dq("2026-11-11T11:30:00Z", pass("complete")), cond, false},
		{"too old", dq("2026-11-11T10:59:59Z", pass("complete"), pass("schema")), cond, false},
		{"exactly the limit", dq("2026-11-11T11:00:00Z", pass("complete"), pass("schema")), cond, true},
		{"dated after the decision", dq("2026-11-11T12:00:01Z", pass("complete"), pass("schema")), cond, false},
		{"as_of unreadable", dq("yesterday", pass("complete"), pass("schema")), cond, false},
	}
	for _, c := range cases {
		ctx := &EvaluationContext{ClockEpoch: clock, DataQuality: c.data}
		if got := matchOneCondition("r", c.cond, ctx); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Round 64: every setup fact a policy can name is read from the group of the
// party that states it, and a fact in the other group is never read for it.
func TestSetupFactsAreReadFromTheirOwnGroup(t *testing.T) {
	full := &Setup{
		DeclaredByCaller: &DeclaredSetup{ModelProvider: "p", ModelName: "n", ModelVersion: "v", ModelTemperature: "0.2",
			PromptHash: "h", ClientName: "cn", ClientVersion: "cv"},
		AttestedByVerdifax: &AttestedSetup{ReviewModel: "rm", ReviewPromptID: "rp", ReviewCheckerID: "rc"},
	}
	want := map[string]string{"model_provider": "p", "model_name": "n", "model_version": "v", "model_temperature": "0.2",
		"prompt_hash": "h", "client_name": "cn", "client_version": "cv", "review_model": "rm", "review_prompt_id": "rp",
		"review_checker_id": "rc"}
	if len(SetupFacts) != len(want) {
		t.Fatalf("%d setup facts, want %d", len(SetupFacts), len(want))
	}
	for _, fact := range SetupFacts {
		if got, stated := full.Fact(fact); !stated || got != want[fact] {
			t.Errorf("%s: %q %v, want %q", fact, got, stated, want[fact])
		}
		if SetupFactSource(fact) == "" {
			t.Errorf("%s names no party that states it", fact)
		}
	}
	callerOnly := &Setup{DeclaredByCaller: full.DeclaredByCaller}
	for _, fact := range []string{"review_model", "review_prompt_id", "review_checker_id"} {
		if _, stated := callerOnly.Fact(fact); stated {
			t.Errorf("%s is stated by Verdifax's review only", fact)
		}
		if SetupFactSource(fact) != SetupAttestedByVerdifax {
			t.Errorf("%s is attested by Verdifax", fact)
		}
	}
	if _, stated := (*Setup)(nil).Fact("model_name"); stated || SetupFactSource("actor_id") != "" {
		t.Fatal("no setup states nothing, and actor_id is not a setup fact")
	}
}

// Round 64, R304: a sealed input with no setup and no data use encodes
// exactly as before the fields existed.
func TestAbsentSetupAndDataUseEncodeAsBefore(t *testing.T) {
	in := Inputs{SubjectID: "a", SubjectType: SubjectTypeAgent, Verb: "v", ObjectType: ObjectTypeData, ObjectID: "o",
		Classification: ClassificationInternal, EvaluatedAt: "2026-11-17T00:00:00Z"}
	got, encodeErr := json.Marshal(in)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	const before = `{"subject_id":"a","subject_type":"agent","verb":"v","object_type":"data","object_id":"o","classification":"INTERNAL","evaluated_at":"2026-11-17T00:00:00Z"}`
	if string(got) != before {
		t.Fatalf("got %s, want %s", got, before)
	}
}

// Round 64: the review facts a rule names are held after the review, against
// what Verdifax's AI review stated; the decision itself never reads them.
func TestReviewSetupIsHeldAgainstTheReview(t *testing.T) {
	rule := &Rule{RuleID: "r", Effect: EffectAllow, Conditions: []Condition{
		{Type: ConditionAttestedSetup, Facts: []SetupFactMatch{
			{Fact: "model_name", Match: Matcher{Operator: MatchAny}},
			{Fact: "review_prompt_id", Match: Matcher{Operator: MatchExact, Value: "statements-v1"}},
			{Fact: "review_model", Match: Matcher{Operator: MatchPrefix, Value: "claude-"}},
		}},
		{Type: ConditionMFARequired, Required: false},
	}}
	named := ReviewSetupNamed(rule)
	if len(named) != 2 || named[0].Fact != "review_prompt_id" || named[1].Fact != "review_model" {
		t.Fatalf("named %+v, want the two review facts in the rule's order", named)
	}
	if fact, _ := ReviewSetupMismatch(named, &AttestedSetup{ReviewModel: "claude-opus-5-5", ReviewPromptID: "statements-v1"}); fact != "" {
		t.Fatalf("a matching review is held as a mismatch on %s", fact)
	}
	if fact, value := ReviewSetupMismatch(named, &AttestedSetup{ReviewModel: "gpt-9", ReviewPromptID: "statements-v1"}); fact != "review_model" || value != "gpt-9" {
		t.Fatalf("got %s %q, want review_model gpt-9", fact, value)
	}
	if fact, value := ReviewSetupMismatch(named, nil); fact != "review_prompt_id" || value != "" {
		t.Fatalf("no review states nothing: got %s %q", fact, value)
	}
	if ReviewSetupNamed(nil) != nil || ReviewSetupNamed(&Rule{}) != nil {
		t.Fatal("no rule names no review fact")
	}
}

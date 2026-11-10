package psleval

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
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
		RateCounts: map[string]int{"r": 1}}
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

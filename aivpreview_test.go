package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

const reviewTrace = "The vault is always locked.\n\nThe vault is never locked."

func reviewBlock(mode, outcome string, finding bool) *artifacts.AivpReview {
	sum := sha256.Sum256([]byte(reviewTrace))
	r := &artifacts.AivpReview{Formula: artifacts.AivpReviewFormulaV1, PromptID: "statements-v1", Model: "claude-opus-5-5",
		TraceHash: hex.EncodeToString(sum[:]), CheckerID: "keyword-v1", ContradictionMode: mode, ContradictionOutcome: outcome}
	if finding {
		r.Finding = &artifacts.AivpFinding{NodeA: "node-0001", NodeB: "node-0002", Term: "always", Opposite: "never"}
	}
	return r
}

func TestAnAIReviewBlockMustBeConsistent(t *testing.T) {
	for name, c := range map[string]struct {
		review   *artifacts.AivpReview
		released bool
		ok       bool
	}{
		"recorded on a released step": {reviewBlock("record", "recorded", true), true, true},
		"halted on a halt receipt":    {reviewBlock("halt", "halted", true), false, true},
		"clean":                       {reviewBlock("halt", "clean", false), true, true},
		"halted on a released step":   {reviewBlock("halt", "halted", true), true, false},
		"recorded under halt mode":    {reviewBlock("halt", "recorded", true), true, false},
		"clean with a finding":        {reviewBlock("record", "clean", true), true, false},
		"recorded with no finding":    {reviewBlock("record", "recorded", false), true, false},
		"an unknown mode":             {reviewBlock("warn", "clean", false), true, false},
		"a checker this release cannot re-run": {func() *artifacts.AivpReview {
			r := reviewBlock("halt", "clean", false)
			r.CheckerID = "llm-v1"
			return r
		}(), true, false},
		"an unknown form": {func() *artifacts.AivpReview {
			r := reviewBlock("halt", "clean", false)
			r.Formula = "aivp-review.v9"
			return r
		}(), true, false},
		"no model named": {func() *artifacts.AivpReview { r := reviewBlock("halt", "clean", false); r.Model = ""; return r }(), true, false},
	} {
		c := c
		got := aiReviewOf(c.review, c.released)
		if got.Consistent != c.ok || aiReviewFailed(got) == c.ok {
			t.Errorf("%s: consistent %v (%s), want %v", name, got.Consistent, got.Reason, c.ok)
		}
	}
	if aiReviewOf(nil, true) != nil {
		t.Error("a record with no review block has no review check")
	}
}

func TestTheTraceIsCheckedAgainstTheSealedReview(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := applyAIReviewTrace(aiReviewOf(reviewBlock("record", "recorded", true), true), write("good.txt", reviewTrace))
	if !good.TraceChecked || !good.TraceMatch || aiReviewFailed(good) {
		t.Fatalf("the sealed trace must re-check: %+v", good)
	}
	other := applyAIReviewTrace(aiReviewOf(reviewBlock("record", "recorded", true), true), write("other.txt", reviewTrace+" "))
	if other.TraceMatch || !aiReviewFailed(other) || !strings.Contains(other.Reason, "SHA-256") {
		t.Fatalf("another trace must fail on its hash: %+v", other)
	}
	// A forged block whose finding names other terms fails on the re-run
	// even though the trace hash matches.
	forged := reviewBlock("record", "recorded", true)
	forged.Finding.Term, forged.Finding.Opposite = "true", "false"
	bad := applyAIReviewTrace(aiReviewOf(forged, true), write("same.txt", reviewTrace))
	if bad.TraceMatch || !aiReviewFailed(bad) || !strings.Contains(bad.Reason, "does not reach") {
		t.Fatalf("a finding the trace does not hold must fail: %+v", bad)
	}
	none := applyAIReviewTrace(nil, write("x.txt", reviewTrace))
	if !aiReviewFailed(none) {
		t.Fatal("--aivp-trace on a record with no review must fail, not pass silently")
	}
}

func TestTheSealedModeMustBeThePolicysChoice(t *testing.T) {
	policy := []byte(`{"schema":"psl.v1","policy_id":"p","policy_name":"P","policy_version":"1","effective_at":"2026-01-01T00:00:00Z","default_effect":"deny",
 "ai_review":{"contradiction":"halt"},
 "rules":[{"rule_id":"texts","effect":"allow","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"text","id_match":{"operator":"any"}},"ai_review":{"contradiction":"record"}},
          {"rule_id":"actions","effect":"allow","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"transaction","id_match":{"operator":"any"}}}]}`)
	gate := func(rule string) *PolicyGateCheck {
		return &PolicyGateCheck{Present: true, Outcome: "allow", FiredRuleID: rule}
	}
	for _, c := range []struct {
		rule, mode string
		ok         bool
	}{{"texts", "record", true}, {"actions", "halt", true}, {"texts", "halt", false}, {"actions", "record", false}} {
		outcome := map[string]string{"record": "recorded", "halt": "halted"}[c.mode]
		got := applyAIReviewMode(aiReviewOf(reviewBlock(c.mode, outcome, true), c.mode == "record"), policy, gate(c.rule))
		if !got.ModeChecked || got.ModeMatch != c.ok || aiReviewFailed(got) == c.ok {
			t.Errorf("rule %s sealed %s: %+v, want match %v", c.rule, c.mode, got, c.ok)
		}
	}
}

func TestAJobStepsTraceIsRequiredAndChecked(t *testing.T) {
	dir := t.TempDir()
	opts := jobOptions{traceDir: dir}
	review := func() *AIReviewCheck { return aiReviewOf(reviewBlock("record", "recorded", true), true) }
	if reason := jobStepTrace("rule-03.json", review(), opts); !strings.Contains(reason, "rule-03.txt") {
		t.Fatalf("a missing trace must fail naming the file: %q", reason)
	}
	if err := os.WriteFile(filepath.Join(dir, "rule-03.txt"), []byte("another text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reason := jobStepTrace("rule-03.json", review(), opts); reason == "" {
		t.Fatal("a trace that is not the sealed one must fail")
	}
	if err := os.WriteFile(filepath.Join(dir, "rule-03.txt"), []byte(reviewTrace), 0o600); err != nil {
		t.Fatal(err)
	}
	if reason := jobStepTrace("rule-03.json", review(), opts); reason != "" {
		t.Fatalf("the sealed trace must pass: %q", reason)
	}
	if reason := jobStepTrace("verdict.json", nil, opts); reason != "" {
		t.Fatalf("a step with no review needs no trace: %q", reason)
	}
	if reason := jobStepTrace("rule-03.json", review(), jobOptions{}); reason != "" {
		t.Fatal("without --aivp-traces nothing is required")
	}
}

// Round 56, F1: on a step that sealed no AI review, --aivp-trace with the
// account policy reports that the record has no review to compare the trace
// with. The policy's contradiction check once ran on the empty review and
// replaced that reason with a truncated one ("... but the record seals ").
func TestATraceForAStepWithNoReviewKeepsItsReason(t *testing.T) {
	c := applyAIReviewTrace(nil, "traces/verdict.txt")
	gate := &PolicyGateCheck{Present: true, Outcome: "allow", FiredRuleID: "review-steps"}
	c = applyAIReviewMode(c, []byte(`{"not":"read"}`), gate)
	if c.ModeChecked || c.Reason != "--aivp-trace given, but this record seals no AI review to compare it with" {
		t.Fatalf("the trace check's reason must stand: %+v", c)
	}
	if !aiReviewFailed(c) {
		t.Fatal("a trace given for a step with no review must still fail the check, as the documented exit code says")
	}
}

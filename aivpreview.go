package main

// AI review checks (v0.27.0). A record whose AI review ran carries a review
// block (aivp_t4.review in a bundle, review in an AI review halt receipt):
// the review setup, the SHA-256 of the trace the check ran on, the checker,
// what the account policy chose a contradiction finding does (halt or
// record), the outcome and the finding. This file checks the block is
// consistent with itself and with the record; with --aivp-trace it re-runs
// the contradiction check on the trace the record's owner kept and requires
// the sealed hash and finding; with --account-policy it requires the sealed
// choice to be the one the account policy's fired rule makes.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Verdifax/verdifax-verify/internal/aivpcheck"
	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/psleval"
)

// AIReviewCheck is what this tool found about a record's AI review.
type AIReviewCheck struct {
	Present    bool                   `json:"present"`
	PromptID   string                 `json:"prompt_id,omitempty"`
	Model      string                 `json:"model,omitempty"`
	TraceHash  string                 `json:"trace_hash,omitempty"`
	CheckerID  string                 `json:"checker_id,omitempty"`
	Mode       string                 `json:"contradiction_mode,omitempty"`
	Outcome    string                 `json:"contradiction_outcome,omitempty"`
	Finding    *artifacts.AivpFinding `json:"finding,omitempty"`
	Consistent bool                   `json:"consistent"`
	// TraceChecked is true when --aivp-trace was given; TraceMatch when the
	// file's SHA-256 is the sealed trace hash and the check run again on it
	// reaches the sealed finding, or none.
	TraceChecked bool `json:"trace_checked"`
	TraceMatch   bool `json:"trace_match"`
	// ModeChecked is true when --account-policy was given and the record
	// seals the account policy's decision; ModeMatch when the sealed choice
	// is the one the fired rule (or the policy) makes.
	ModeChecked bool   `json:"mode_checked"`
	ModeMatch   bool   `json:"mode_match"`
	Reason      string `json:"reason,omitempty"`
}

// aiReviewOf checks a sealed review block. released is true for a record
// whose review let the step continue and false for a halt receipt. A nil
// block (no review ran, or a record sealed before the block existed) gives
// nil.
func aiReviewOf(review *artifacts.AivpReview, released bool) *AIReviewCheck {
	if review == nil {
		return nil
	}
	c := &AIReviewCheck{Present: true, PromptID: review.PromptID, Model: review.Model, TraceHash: review.TraceHash,
		CheckerID: review.CheckerID, Mode: review.ContradictionMode, Outcome: review.ContradictionOutcome, Finding: review.Finding}
	c.Reason = reviewInconsistency(review, released)
	c.Consistent = c.Reason == ""
	return c
}

func reviewInconsistency(r *artifacts.AivpReview, released bool) string {
	switch {
	case r.Formula != artifacts.AivpReviewFormulaV1:
		return fmt.Sprintf("the AI review block is form %q, which this release does not read", r.Formula)
	case r.CheckerID != aivpcheck.CheckerKeywordV1:
		return fmt.Sprintf("the AI review names checker %q, which this release cannot re-run", r.CheckerID)
	case !psleval.KnownContradictionMode(psleval.ContradictionMode(r.ContradictionMode)):
		return fmt.Sprintf("the AI review's contradiction mode %q is neither halt nor record", r.ContradictionMode)
	case len(r.TraceHash) != 64:
		return "the AI review's trace hash is not a SHA-256"
	case r.PromptID == "" || r.Model == "":
		return "the AI review does not name its prompt and model"
	}
	want := "clean"
	if r.Finding != nil {
		want = map[string]string{"halt": "halted", "record": "recorded"}[r.ContradictionMode]
	}
	if r.ContradictionOutcome != want {
		return fmt.Sprintf("the AI review's outcome is %q, but its finding and mode make it %q", r.ContradictionOutcome, want)
	}
	if released && want == "halted" {
		return "the AI review halted the step, yet the record says the step was released"
	}
	return ""
}

// applyAIReviewTrace re-runs the contradiction check on the trace file.
func applyAIReviewTrace(c *AIReviewCheck, path string) *AIReviewCheck {
	if path == "" {
		return c
	}
	if c == nil {
		return &AIReviewCheck{TraceChecked: true, Reason: "--aivp-trace given, but this record seals no AI review to compare it with"}
	}
	c.TraceChecked = true
	text, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --aivp-trace:", readErr)
		os.Exit(2)
	}
	sum := sha256.Sum256(text)
	if hex.EncodeToString(sum[:]) != c.TraceHash {
		c.Reason = "the --aivp-trace file is not the trace this record's AI review sealed (its SHA-256 differs)"
		return c
	}
	got := aivpcheck.KeywordV1(aivpcheck.ParseTrace(string(text)))
	if !sameReviewFinding(got, c.Finding) {
		c.Reason = "the contradiction check run again on the trace does not reach the finding the record seals"
		return c
	}
	c.TraceMatch = true
	return c
}

func sameReviewFinding(got *aivpcheck.Finding, sealed *artifacts.AivpFinding) bool {
	if got == nil || sealed == nil {
		return got == nil && sealed == nil
	}
	return got.NodeA == sealed.NodeA && got.NodeB == sealed.NodeB && got.Term == sealed.Term && got.Opposite == sealed.Opposite
}

// applyAIReviewMode requires the sealed contradiction mode to be the one the
// account policy document makes for the rule the record says fired. The
// document itself is checked against the sealed hashes by --account-policy.
func applyAIReviewMode(c *AIReviewCheck, doc []byte, gate *PolicyGateCheck) *AIReviewCheck {
	// The policy's contradiction choice governs only a step that sealed an
	// AI review. A step that declared no AI output records no review, a
	// sealed state of its own, and keeps the reason the trace check gave
	// (round 56, F1: this once replaced it with a truncated mode message).
	if c == nil || !c.Present || doc == nil || gate == nil || !gate.Present || gate.Outcome != string(psleval.EffectAllow) {
		return c
	}
	c.ModeChecked = true
	policy, readErr := psleval.ReadDocument(doc)
	if readErr != nil {
		c.Reason = "the account policy could not be read to check the AI review's mode: " + readErr.Error()
		return c
	}
	var fired *psleval.Rule
	for i := range policy.Rules {
		if policy.Rules[i].RuleID == gate.FiredRuleID {
			fired = &policy.Rules[i]
		}
	}
	want := psleval.ContradictionModeFor(fired, policy.AIReview)
	if string(want) != c.Mode {
		sealed := c.Mode
		if sealed == "" {
			sealed = "no contradiction choice"
		}
		c.Reason = fmt.Sprintf("the account policy's rule %q makes a contradiction %s, but the record seals %s", gate.FiredRuleID, want, sealed)
		return c
	}
	c.ModeMatch = true
	return c
}

// aiReviewFailed reports whether the review check fails the verification.
func aiReviewFailed(c *AIReviewCheck) bool {
	return c != nil && (!c.Present || !c.Consistent || (c.TraceChecked && !c.TraceMatch) || (c.ModeChecked && !c.ModeMatch))
}

func printAIReview(c *AIReviewCheck) {
	if c == nil {
		return
	}
	fmt.Println("  AI review:")
	if !c.Present {
		fmt.Printf("    %s\n", c.Reason)
		return
	}
	fmt.Printf("    setup:             prompt %s on %s, checker %s\n", c.PromptID, c.Model, c.CheckerID)
	fmt.Printf("    policy chose:      a contradiction %s\n", map[string]string{"halt": "halts the step", "record": "is recorded and the step continues"}[c.Mode])
	if c.Finding != nil {
		fmt.Printf("    found:             %q in %s against %q in %s (%s)\n", c.Finding.Term, c.Finding.NodeA, c.Finding.Opposite, c.Finding.NodeB, c.Outcome)
	} else {
		fmt.Println("    found:             no contradiction")
	}
	fmt.Printf("    trace sha256:      %s\n", c.TraceHash)
	switch {
	case !c.Consistent:
		fmt.Printf("    FAILED: %s\n", c.Reason)
	case c.TraceChecked && !c.TraceMatch:
		fmt.Printf("    FAILED: %s\n", c.Reason)
	case c.TraceChecked:
		fmt.Println("    re-checked:        the trace file hashes to the sealed hash, and the check run again reaches the sealed result")
	default:
		fmt.Println("    re-check:          pass the trace with --aivp-trace to re-run the check offline")
	}
	switch {
	case c.ModeChecked && !c.ModeMatch:
		fmt.Printf("    FAILED: %s\n", c.Reason)
	case c.ModeChecked:
		fmt.Println("    policy choice:     the account policy's fired rule makes this choice")
	}
}

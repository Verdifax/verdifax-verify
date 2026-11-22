package policyhash

// The round 64 policy fields (v0.38.0), a port of the server's
// psl/round64.go: a setup watch (watch_setup), a review date (review),
// response targets for refusals and stops (response_targets), a response
// target on a rule's sign-off (signoff.within with compare, notice and
// seal_in_result), and two condition types, attested_setup and data_use.
// The reader models and checks each as the server's psl.Validate does, and
// each joins the policy hash only when present, so every policy written
// without them hashes exactly as before. Verifier v0.37.0 refuses a policy
// that carries any of them, as an unknown key.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// setupFactNames is every setup fact by its sealed name, in the server's
// fixed order (psleval.SetupFacts; a test holds the two in step).
var setupFactNames = []string{"model_provider", "model_name", "model_version", "model_temperature", "prompt_hash",
	"client_name", "client_version", "review_model", "review_prompt_id", "review_checker_id"}

// The server's limits on the round 64 fields.
const (
	maxResponseTargetSeconds = 366 * 24 * 3600
	maxReviewIntervalDays    = 3660
)

// The refusals of a malformed round 64 field, named as the server names them.
var (
	ErrInvalidWatchSetup     = errors.New("policyhash: invalid watch_setup")
	ErrInvalidReview         = errors.New("policyhash: invalid review")
	ErrInvalidResponseTarget = errors.New("policyhash: invalid response target")
	ErrInvalidSignOff        = errors.New("policyhash: invalid signoff")
)

// checkRound64 is the server's checkRound64, which psl.Validate runs.
func checkRound64(p *policy) error {
	if w := p.WatchSetup; w != nil {
		if fieldsErr := checkSetupFactNames(w.Fields); fieldsErr != nil {
			return fmt.Errorf("%w: fields %v", ErrInvalidWatchSetup, fieldsErr)
		}
		if w.Scope != "account" && w.Scope != "key" {
			return fmt.Errorf("%w: scope must be account or key, not %q", ErrInvalidWatchSetup, w.Scope)
		}
	}
	if r := p.Review; r != nil {
		switch {
		case (r.ReviewBy == "") == (r.IntervalDays == 0):
			return fmt.Errorf("%w: set exactly one of review_by and interval_days", ErrInvalidReview)
		case r.IntervalDays < 0 || r.IntervalDays > maxReviewIntervalDays:
			return fmt.Errorf("%w: interval_days must be from 1 to %d", ErrInvalidReview, maxReviewIntervalDays)
		case r.ReviewBy != "":
			by, byErr := time.Parse(time.RFC3339, r.ReviewBy)
			if byErr != nil {
				return fmt.Errorf("%w: review_by %q is not an RFC 3339 time", ErrInvalidReview, r.ReviewBy)
			}
			if effective, effectiveErr := time.Parse(time.RFC3339, p.EffectiveAt); effectiveErr == nil && !by.After(effective) {
				return fmt.Errorf("%w: review_by must be after effective_at", ErrInvalidReview)
			}
		}
	}
	if t := p.ResponseTargets; t != nil {
		if t.Refusals == nil && t.Stops == nil {
			return fmt.Errorf("%w: response_targets sets neither refusals nor stops; leave it out to set none", ErrInvalidResponseTarget)
		}
		for _, named := range []struct {
			name   string
			target *responseTarget
		}{{"refusals", t.Refusals}, {"stops", t.Stops}} {
			if named.target == nil {
				continue
			}
			if targetErr := checkTarget(named.target.Within, named.target.Compare, named.target.Notice); targetErr != nil {
				return fmt.Errorf("%w: response_targets.%s %v", ErrInvalidResponseTarget, named.name, targetErr)
			}
		}
	}
	return nil
}

// checkSignOffTarget is the server's: a sign-off's response target is set
// only with within, and then whole.
func checkSignOffTarget(ruleID string, s *signOff) error {
	if s == nil || (s.Within == 0 && s.Compare == "" && s.Notice == "" && !s.SealInResult) {
		return nil
	}
	if s.Within == 0 {
		return fmt.Errorf("%w: rule %q sets compare, notice or seal_in_result without within", ErrInvalidSignOff, ruleID)
	}
	if targetErr := checkTarget(s.Within, s.Compare, s.Notice); targetErr != nil {
		return fmt.Errorf("%w: rule %q %v", ErrInvalidSignOff, ruleID, targetErr)
	}
	return nil
}

func checkTarget(within int, compare, notice string) error {
	if within < 1 || within > maxResponseTargetSeconds {
		return fmt.Errorf("within must be from 1 to %d seconds", maxResponseTargetSeconds)
	}
	switch compare {
	case "first_signoff", "first_approval", "decision_in_force":
	default:
		return fmt.Errorf("compare must be first_signoff, first_approval or decision_in_force, not %q", compare)
	}
	switch notice {
	case "event", "head", "both":
	default:
		return fmt.Errorf("notice must be event, head or both, not %q", notice)
	}
	return nil
}

// checkSetupFactNames requires one or more distinct setup facts.
func checkSetupFactNames(names []string) error {
	if len(names) == 0 || len(names) > len(setupFactNames) {
		return fmt.Errorf("must name from 1 to %d setup facts", len(setupFactNames))
	}
	known := map[string]bool{}
	for _, f := range setupFactNames {
		known[f] = true
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !known[name] {
			return fmt.Errorf("names %q, which is not a setup fact (%s)", name, strings.Join(setupFactNames, ", "))
		}
		if seen[name] {
			return fmt.Errorf("names %q twice", name)
		}
		seen[name] = true
	}
	return nil
}

// round64Preimage is the server's: the round 64 top-level fields, each only
// when present.
func round64Preimage(p *policy, out map[string]any) {
	if w := p.WatchSetup; w != nil {
		watch := map[string]any{"fields": stringsAsAny(w.Fields), "scope": w.Scope}
		if w.IncludeRefused {
			watch["include_refused"] = true
		}
		out["watch_setup"] = watch
	}
	if r := p.Review; r != nil {
		review := map[string]any{}
		if r.ReviewBy != "" {
			review["review_by"] = r.ReviewBy
		}
		if r.IntervalDays != 0 {
			review["interval_days"] = r.IntervalDays
		}
		out["review"] = review
	}
	if t := p.ResponseTargets; t != nil {
		targets := map[string]any{}
		if t.Refusals != nil {
			targets["refusals"] = targetPreimage(t.Refusals.Within, t.Refusals.Compare, t.Refusals.Notice, t.Refusals.SealInResult)
		}
		if t.Stops != nil {
			targets["stops"] = targetPreimage(t.Stops.Within, t.Stops.Compare, t.Stops.Notice, t.Stops.SealInResult)
		}
		out["response_targets"] = targets
	}
}

// signOffPreimage is a rule's sign-off as the hash covers it: required, and
// its response target only when set.
func signOffPreimage(s *signOff) map[string]any {
	out := map[string]any{"required": true}
	if s.Within != 0 {
		for k, v := range targetPreimage(s.Within, s.Compare, s.Notice, s.SealInResult) {
			out[k] = v
		}
	}
	return out
}

func targetPreimage(within int, compare, notice string, seal bool) map[string]any {
	out := map[string]any{"within": within, "compare": compare, "notice": notice}
	if seal {
		out["seal_in_result"] = true
	}
	return out
}

// round64ConditionPreimage is the server's: an attested_setup or data_use
// condition's settings, each only when set.
func round64ConditionPreimage(c condition, out map[string]any) {
	switch c.Type {
	case "attested_setup":
		facts := make([]any, len(c.Facts))
		for i, f := range c.Facts {
			facts[i] = map[string]any{"fact": f.Fact, "match": matcherPreimage(f.Match)}
		}
		out["facts"] = facts
	case "data_use":
		if c.PurposeMatch != nil {
			out["purpose_match"] = matcherPreimage(*c.PurposeMatch)
		}
		if c.BasisMatch != nil {
			out["basis_match"] = matcherPreimage(*c.BasisMatch)
		}
		if len(c.CategoriesAllowed) > 0 {
			out["categories_allowed"] = stringsAsAny(c.CategoriesAllowed)
		}
		if c.ReferenceRequired {
			out["reference_required"] = true
		}
	}
}

// ReviewDeclaration reads a policy document the way FromDocument does and
// returns its review date declaration (round 64): review_by or interval_days,
// or both empty when it declares none.
func ReviewDeclaration(doc []byte) (reviewBy string, intervalDays int, declared bool, err error) {
	if _, readErr := FromDocument(doc); readErr != nil {
		return "", 0, false, readErr
	}
	p, parseErr := parsed(doc)
	if parseErr != nil {
		return "", 0, false, parseErr
	}
	if p.Review == nil {
		return "", 0, false, nil
	}
	return p.Review.ReviewBy, p.Review.IntervalDays, true, nil
}

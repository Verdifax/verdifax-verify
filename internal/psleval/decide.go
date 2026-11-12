package psleval

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrUnreadable means a rule depends on something the decision cannot read: a
// time or classification that does not parse, or a type or operator this
// engine does not know. Passing over such a rule would quietly remove it, so
// the decision stops instead and the run is refused.
var ErrUnreadable = errors.New("psleval: a rule depends on a value that cannot be read")

// Result is what a decision reached.
type Result struct {
	Outcome     Effect
	FiredRuleID string
	ReasonCode  string
}

// Document is the part of a policy a decision reads.
type Document struct {
	DefaultEffect Effect    `json:"default_effect"`
	Rules         []Rule    `json:"rules"`
	AIReview      *AIReview `json:"ai_review,omitempty"`
}

// ReadDocument reads the rules out of a policy's exact text.
func ReadDocument(doc []byte) (Document, error) {
	var d Document
	if parseErr := json.Unmarshal(doc, &d); parseErr != nil {
		return Document{}, fmt.Errorf("psleval: read policy: %w", parseErr)
	}
	return d, nil
}

// Decide applies rules in order: the first rule that matches fires, and with
// none the default effect applies. The same rules and context always give the
// same result. Every rule is checked as readable first, so a rule that sits
// after the one that fires cannot hide a broken one.
func Decide(rules []Rule, defaultEffect Effect, ctx *EvaluationContext) (Result, error) {
	if readErr := checkReadable(rules, ctx); readErr != nil {
		return Result{}, readErr
	}
	for i := range rules {
		rule := &rules[i]
		if !matchSubject(rule.Subject, ctx) || !matchVerb(rule.Verb, ctx) ||
			!matchObject(rule.Object, ctx) || !matchConditions(rule.RuleID, rule.Conditions, ctx) {
			continue
		}
		reason := reasonFor(rule.Effect)
		if rule.ReasonCodeOverride != "" {
			reason = rule.ReasonCodeOverride
		}
		return Result{Outcome: rule.Effect, FiredRuleID: rule.RuleID, ReasonCode: reason}, nil
	}
	return Result{Outcome: defaultEffect, FiredRuleID: DefaultRuleID, ReasonCode: ReasonDefaultEffectApplied}, nil
}

// DecideDocument decides with a whole policy: Decide, then a step the policy
// allows is refused, with ReasonAIReviewRequired and the rule that allowed
// it, when the policy requires an AI review and the request declared no AI
// output (round 56).
func DecideDocument(d Document, ctx *EvaluationContext) (Result, error) {
	result, err := Decide(d.Rules, d.DefaultEffect, ctx)
	if err != nil || result.Outcome != EffectAllow || ctx.AIOutputDeclared {
		return result, err
	}
	var fired *Rule
	for i := range d.Rules {
		if d.Rules[i].RuleID == result.FiredRuleID {
			fired = &d.Rules[i]
		}
	}
	if ReviewRequired(fired, d.AIReview) {
		return Result{Outcome: EffectDeny, FiredRuleID: result.FiredRuleID, ReasonCode: ReasonAIReviewRequired}, nil
	}
	return result, nil
}

func checkReadable(rules []Rule, ctx *EvaluationContext) error {
	for i := range rules {
		rule := &rules[i]
		matchers := []Matcher{rule.Subject.IDMatch, rule.Verb.Match, rule.Object.IDMatch}
		if rule.Subject.RoleMatch != nil {
			matchers = append(matchers, *rule.Subject.RoleMatch)
		}
		for _, m := range matchers {
			if !knownOperator(m.Operator) {
				return fmt.Errorf("%w: rule %q uses operator %q", ErrUnreadable, rule.RuleID, m.Operator)
			}
		}
		for _, bound := range []ClassificationLevel{rule.Object.ClassificationMax, rule.Object.ClassificationMin} {
			if bound == "" {
				continue
			}
			if !KnownClassification(bound) || !KnownClassification(ctx.Classification) {
				return fmt.Errorf("%w: rule %q compares classification %q with %q", ErrUnreadable, rule.RuleID, ctx.Classification, bound)
			}
		}
		for _, c := range rule.Conditions {
			if condErr := checkCondition(rule.RuleID, c, ctx); condErr != nil {
				return condErr
			}
		}
	}
	return nil
}

func checkCondition(ruleID string, c Condition, ctx *EvaluationContext) error {
	switch c.Type {
	case ConditionMFARequired, ConditionMinSessionAge, ConditionRequiresRole, ConditionRateLimit:
		return nil
	case ConditionDataQuality:
		// The data's own as_of may be anything a caller wrote; a bad one
		// makes the condition fail. The decision's clock must be readable.
		if _, clockErr := time.Parse(time.RFC3339, ctx.ClockEpoch); c.MaxAgeSeconds > 0 && clockErr != nil {
			return fmt.Errorf("%w: rule %q has a data_quality age at clock %q", ErrUnreadable, ruleID, ctx.ClockEpoch)
		}
		return nil
	case ConditionTimeWindow:
		_, startOK := ParseHHMM(c.StartUTC)
		_, endOK := ParseHHMM(c.EndUTC)
		_, clockOK := minutesOfDay(ctx.ClockEpoch)
		if startOK && endOK && clockOK {
			return nil
		}
		return fmt.Errorf("%w: rule %q has time window %q to %q at %q", ErrUnreadable, ruleID, c.StartUTC, c.EndUTC, ctx.ClockEpoch)
	default:
		return fmt.Errorf("%w: rule %q has condition %q", ErrUnreadable, ruleID, c.Type)
	}
}

func matchSubject(s Subject, ctx *EvaluationContext) bool {
	if s.Type != SubjectTypeAny && s.Type != ctx.SubjectType {
		return false
	}
	if !Match(s.IDMatch, ctx.SubjectID) {
		return false
	}
	return s.RoleMatch == nil || Match(*s.RoleMatch, ctx.SubjectRole)
}

func matchVerb(v Verb, ctx *EvaluationContext) bool {
	return Match(v.Match, ctx.Verb)
}

func matchObject(o Object, ctx *EvaluationContext) bool {
	if o.Type != ObjectTypeAny && o.Type != ctx.ObjectType {
		return false
	}
	if !Match(o.IDMatch, ctx.ObjectID) {
		return false
	}
	if o.ClassificationMax != "" {
		if cmp, ok := CompareClassification(ctx.Classification, o.ClassificationMax); !ok || cmp > 0 {
			return false
		}
	}
	if o.ClassificationMin != "" {
		if cmp, ok := CompareClassification(ctx.Classification, o.ClassificationMin); !ok || cmp < 0 {
			return false
		}
	}
	return true
}

// matchConditions reports whether every condition holds: they combine with AND.
func matchConditions(ruleID string, conds []Condition, ctx *EvaluationContext) bool {
	for _, c := range conds {
		if !matchOneCondition(ruleID, c, ctx) {
			return false
		}
	}
	return true
}

func matchOneCondition(ruleID string, c Condition, ctx *EvaluationContext) bool {
	switch c.Type {
	case ConditionMFARequired:
		return !c.Required || ctx.MFASatisfied
	case ConditionMinSessionAge:
		return ctx.SessionAgeSeconds >= c.Seconds
	case ConditionRequiresRole:
		return ctx.SubjectRole == c.Role
	case ConditionTimeWindow:
		return inTimeWindow(c.StartUTC, c.EndUTC, ctx.ClockEpoch)
	case ConditionRateLimit:
		// RateCounts holds the runs this rule has already admitted for this
		// key inside the window. The caller reads it before deciding and seals it.
		return ctx.RateCounts[ruleID] < c.MaxPerWindow
	case ConditionDataQuality:
		return dataQualityHolds(c, ctx)
	default:
		return false
	}
}

// dataQualityHolds reports whether the request's data-quality declaration
// meets a data_quality condition: it was made, every check the condition
// names was declared with the result pass, and, when max_age_seconds is set,
// its as_of is at most that long before the decision and not after it.
func dataQualityHolds(c Condition, ctx *EvaluationContext) bool {
	dq := ctx.DataQuality
	if dq == nil {
		return false
	}
	for _, name := range c.Checks {
		passed := false
		for _, check := range dq.Checks {
			if check.Name == name && check.Result == DataCheckPass {
				passed = true
			}
		}
		if !passed {
			return false
		}
	}
	if c.MaxAgeSeconds > 0 {
		asOf, asOfErr := time.Parse(time.RFC3339, dq.AsOf)
		clock, clockErr := time.Parse(time.RFC3339, ctx.ClockEpoch)
		if asOfErr != nil || clockErr != nil {
			return false
		}
		age := clock.Sub(asOf)
		if age < 0 || age > time.Duration(c.MaxAgeSeconds)*time.Second {
			return false
		}
	}
	return true
}

// inTimeWindow reports whether the time of day falls inside the window, whose
// bounds are included. A start after the end wraps midnight.
func inTimeWindow(startUTC, endUTC, clock string) bool {
	start, _ := ParseHHMM(startUTC)
	end, _ := ParseHHMM(endUTC)
	now, _ := minutesOfDay(clock)
	if start <= end {
		return now >= start && now <= end
	}
	return now >= start || now <= end
}

// ParseHHMM reads a 24-hour "HH:MM" as minutes since midnight.
func ParseHHMM(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// minutesOfDay reads an RFC 3339 time as minutes since midnight UTC.
func minutesOfDay(s string) (int, bool) {
	t, parseErr := time.Parse(time.RFC3339, s)
	if parseErr != nil {
		return 0, false
	}
	t = t.UTC()
	return t.Hour()*60 + t.Minute(), true
}

func reasonFor(e Effect) string {
	switch e {
	case EffectAllow:
		return ReasonRuleAllowed
	case EffectDeny:
		return ReasonRuleDenied
	default:
		return ""
	}
}

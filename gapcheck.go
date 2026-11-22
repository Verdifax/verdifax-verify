package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// Round 62. A refusal for missing fields seals no policy gate: it names the
// policy that required the fields by its hash, id and name, and lists the
// fields required and the fields missing. A policy document given with
// --policy or --account-policy is checked against it: the document must be
// the policy the refusal names, and require exactly the fields the refusal
// says were required, and every field said missing must be one of them.
// Before round 62 a document given with a refusal failed it, as a record with
// no gate to compare. Since round 62 an account policy can refuse a request
// this way, as a key's always could, so a reader holding either document can
// confirm the refusal is that policy's.
func checkGapPolicyDocument(gap *artifacts.AttestationGapReceipt, doc []byte, flag string) PolicyGateCheck {
	c := PolicyGateCheck{Present: true, PolicyID: gap.PolicyID, PolicyName: gap.PolicyName, PolicyHash: gap.PolicyHash,
		DecisionReasonCode: gap.DecisionReasonCode, Outcome: "refused", DocumentChecked: true}
	got, docErr := policyhash.FromDocument(doc)
	if docErr != nil {
		c.Reason = fmt.Sprintf("the %s document could not be read as a policy: %v", flag, docErr)
		return c
	}
	docRequired, requiredErr := policyhash.RequiredAttestedFields(doc)
	if requiredErr != nil {
		c.Reason = fmt.Sprintf("the %s document's required fields could not be read: %v", flag, requiredErr)
		return c
	}
	required := append([]string(nil), gap.RequiredFields...)
	sort.Strings(required)
	switch {
	case got.PolicyHash != gap.PolicyHash:
		c.Reason = fmt.Sprintf("the %s document's policy hash %s is not %s, the policy this refusal for missing fields names", flag, got.PolicyHash, gap.PolicyHash)
	case got.PolicyID != gap.PolicyID || got.PolicyName != gap.PolicyName:
		c.Reason = fmt.Sprintf("the %s document is %q %q, the refusal names %q %q", flag, got.PolicyID, got.PolicyName, gap.PolicyID, gap.PolicyName)
	case len(docRequired) == 0:
		c.Reason = fmt.Sprintf("the %s document requires no attested fields, so it refuses no request for missing ones", flag)
	case !reflect.DeepEqual(docRequired, required):
		c.Reason = fmt.Sprintf("the %s document requires %s, the refusal says %s were required", flag,
			strings.Join(docRequired, ", "), strings.Join(required, ", "))
	case len(gap.MissingFields) == 0:
		c.Reason = "the refusal names no missing field"
	default:
		listed := map[string]bool{}
		for _, f := range required {
			listed[f] = true
		}
		for _, f := range gap.MissingFields {
			if !listed[f] {
				c.Reason = fmt.Sprintf("the refusal says %s was missing, which the policy does not require", f)
				return c
			}
		}
		c.DocumentMatch = true
	}
	return c
}

// gapActivationProblem holds the policy change an attestation-gap receipt
// seals as the rule in force (round 64) to its receipt context: the context's
// decision for the same policy must name the same change. A receipt sealed
// without one is checked as before.
func gapActivationProblem(gap *artifacts.AttestationGapReceipt, ctx *artifacts.ReceiptContext) error {
	if gap == nil || gap.ActivationHash == "" || ctx == nil {
		return nil
	}
	for _, b := range []*artifacts.PolicyBinding{ctx.AccountPolicy, ctx.Policy} {
		if b != nil && b.PolicyHash == gap.PolicyHash && b.ActivationHash == gap.ActivationHash {
			return nil
		}
	}
	return fmt.Errorf("the attestation-gap receipt seals policy change %s as the rule in force, and its receipt context names no decision under that change of policy %s",
		truncate(gap.ActivationHash, 16), truncate(gap.PolicyHash, 16))
}

// gapActivationOf is the policy change a refusal for missing fields was made
// under: the one the receipt seals (round 64), or, for a receipt sealed
// without one, the change its context's decision for the same policy names.
func gapActivationOf(gap *artifacts.AttestationGapReceipt, ctx *artifacts.ReceiptContext) string {
	if gap.ActivationHash != "" {
		return gap.ActivationHash
	}
	if ctx == nil {
		return ""
	}
	for _, b := range []*artifacts.PolicyBinding{ctx.AccountPolicy, ctx.Policy} {
		if b != nil && b.PolicyHash == gap.PolicyHash && b.ActivationHash != "" {
			return b.ActivationHash
		}
	}
	return ""
}

// checkRuleInForce matches a refusal for missing fields to the policy change
// in force at its clock in a history (round 64, rule in force): the last
// change activated at or before the gap clock. The change the refusal was made
// under must be that one, and its policy must be the one the receipt names.
// It records the match on the history check, or fails it.
func checkRuleInForce(c *PolicyHistoryCheck, gap *artifacts.AttestationGapReceipt, activation string) {
	if c == nil || !c.OK || gap == nil {
		return
	}
	clock, clockErr := time.Parse(time.RFC3339Nano, gap.GapClock)
	if clockErr != nil {
		c.OK, c.Reason = false, "the refusal's gap_clock is not an RFC 3339 time"
		return
	}
	var inForce *PolicyHistoryEntry
	for i := range c.Entries {
		at, atErr := time.Parse(time.RFC3339Nano, c.Entries[i].ActivatedAt)
		if atErr == nil && !at.After(clock) {
			inForce = &c.Entries[i]
		}
	}
	switch {
	case inForce == nil:
		c.OK, c.Reason = false, fmt.Sprintf("no change in this history was in force at the refusal's clock, %s", gap.GapClock)
	case inForce.ActivationHash != activation:
		c.OK, c.Reason = false, fmt.Sprintf("the refusal was made under policy change %s, and change %d (%s) was the one in force at its clock, %s",
			truncate(activation, 16), inForce.Sequence, truncate(inForce.ActivationHash, 16), gap.GapClock)
	case inForce.PolicyHash != gap.PolicyHash:
		c.OK, c.Reason = false, fmt.Sprintf("change %d, in force at the refusal's clock, put policy %s in force, and the refusal names policy %s",
			inForce.Sequence, truncate(inForce.PolicyHash, 16), truncate(gap.PolicyHash, 16))
	default:
		c.RuleInForce = fmt.Sprintf("decided under change %d of %s, activated at %s, the change in force at the refusal's clock (%s); rule: the policy's required attested fields",
			inForce.Sequence, inForce.ChainID, inForce.ActivatedAt, gap.GapClock)
	}
}

// applyGapRuleInForce matches a refusal for missing fields to the change in
// force at its clock in a history it was made under: one that holds the
// change the refusal names. A history of another chain is checked as before.
func applyGapRuleInForce(r *ReceiptReport, h *PolicyHistoryCheck) {
	if r.gap == nil || h == nil || !h.OK || r.gapActivation == "" {
		return
	}
	for _, e := range h.Entries {
		if e.ActivationHash == r.gapActivation {
			checkRuleInForce(h, r.gap, r.gapActivation)
			return
		}
	}
}

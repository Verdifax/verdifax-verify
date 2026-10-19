package main

import (
	"fmt"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// PolicyGateCheck reports the policy gate's decision an allowed run seals
// in its EPA section (orchestrator releases from October 2026 on), and,
// with --policy, whether a policy document the reader holds is the one
// the gate evaluated.
//
// The values are covered by the EPA section hash, the bundle hash and,
// on complete-record anchored records, the second public-log entry, so
// editing them fails verification. What they cannot show on their own
// is that the named identifier and version belong to the hashed
// document: the record carries the hash, not the policy. --policy
// closes that: the document's recomputed hash must equal the sealed one,
// and its identifier, name and version must equal the sealed values.
type PolicyGateCheck struct {
	Present            bool   `json:"present"`
	PolicyID           string `json:"policy_id,omitempty"`
	PolicyName         string `json:"policy_name,omitempty"`
	PolicyVersion      string `json:"policy_version,omitempty"`
	PolicyHash         string `json:"policy_hash,omitempty"`
	FiredRuleID        string `json:"fired_rule_id,omitempty"`
	DecisionReasonCode string `json:"decision_reason_code,omitempty"`
	DocumentChecked    bool   `json:"document_checked"`
	DocumentMatch      bool   `json:"document_match"`
	Reason             string `json:"reason,omitempty"`
}

// policyGateOf reads the sealed policy gate values.
func policyGateOf(b *artifacts.AuditBundle) PolicyGateCheck {
	pg := b.EPA.PolicyGate
	if pg == nil {
		return PolicyGateCheck{Reason: "no policy gate sealed (record predates it, or the run had no policy gate)"}
	}
	return PolicyGateCheck{
		Present:            true,
		PolicyID:           pg.PolicyID,
		PolicyName:         pg.PolicyName,
		PolicyVersion:      pg.PolicyVersion,
		PolicyHash:         pg.PolicyHash,
		FiredRuleID:        pg.FiredRuleID,
		DecisionReasonCode: pg.DecisionReasonCode,
	}
}

// checkPolicyDocument compares a policy document against the sealed
// policy gate. Error model: every problem becomes the check's reason;
// this binary has no logger.
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
	switch {
	case got.PolicyHash != c.PolicyHash:
		c.Reason = fmt.Sprintf("the document's policy hash %s is not the sealed %s", got.PolicyHash, c.PolicyHash)
	case got.PolicyID != c.PolicyID || got.PolicyName != c.PolicyName || got.PolicyVersion != c.PolicyVersion:
		c.Reason = fmt.Sprintf("the document is %q %q version %q, the record names %q %q version %q",
			got.PolicyID, got.PolicyName, got.PolicyVersion, c.PolicyID, c.PolicyName, c.PolicyVersion)
	default:
		c.DocumentMatch = true
	}
	return c
}

// printPolicyGate renders the policy gate line(s) of the human report.
func printPolicyGate(c PolicyGateCheck) {
	if !c.Present && !c.DocumentChecked {
		fmt.Printf("  Policy gate:      not sealed in this record (%s)\n", c.Reason)
		return
	}
	if c.Present {
		fmt.Printf("  Policy gate:      %s %q version %s, policy hash %s, rule %s (%s)\n",
			c.PolicyID, c.PolicyName, c.PolicyVersion, safePrefix(c.PolicyHash), c.FiredRuleID, c.DecisionReasonCode)
	}
	switch {
	case !c.DocumentChecked:
		fmt.Printf("  Policy document:  not checked; pass --policy FILE to confirm the named policy is the hashed one\n")
	case c.DocumentMatch:
		fmt.Printf("  Policy document:  matches: its recomputed hash, identifier, name and version equal the sealed values\n")
	default:
		fmt.Printf("  Policy document:  ✗ FAILED · %s\n", c.Reason)
	}
}

// applyPolicyDocument records the --policy check on the report; a
// document that does not match fails verification.
func applyPolicyDocument(r *Report, doc []byte) {
	r.PolicyGate = checkPolicyDocument(r.PolicyGate, doc)
	if !r.PolicyGate.DocumentMatch {
		r.AllPassed = false
		r.VerdictTier = "FAILED"
		r.RecordCoverage = "failed"
	}
}

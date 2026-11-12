package main

import (
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 58, B7: a record whose allowing rule requires a person's sign-off
// verifies only with an approval in force on it, matched with the account's
// whole sign-off history, so a later decision cannot be left out. No
// sign-offs or no history given, sign-offs or a history that do not verify,
// and a rejection in force each fail with a reason; a rule that requires none
// adds no check.
func TestASignOffTheRuleRequiresMustBeAnApprovalInForce(t *testing.T) {
	required := func(account bool) *Report {
		r := &Report{}
		if account {
			r.AccountPolicyGate = &PolicyGateCheck{FiredRuleID: "high-risk", SignOffRequired: true}
		} else {
			r.PolicyGate = PolicyGateCheck{FiredRuleID: "high-risk", SignOffRequired: true}
		}
		return r
	}
	if c := signOffRequirement(&Report{PolicyGate: PolicyGateCheck{FiredRuleID: "ordinary"}}, &artifacts.AuditBundle{}); c != nil {
		t.Fatalf("a rule that requires no sign-off adds no check: %+v", c)
	}
	for _, account := range []bool{false, true} {
		r := required(account)
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || c.OK || !strings.Contains(c.Reason, "pass --signoff") || !strings.Contains(c.Reason, "--signoff-history") {
			t.Fatalf("no sign-offs given must fail and say what to pass: %+v", c)
		}
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "approve"}
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || c.OK || !strings.Contains(c.Reason, "--signoff-history") {
			t.Fatalf("an approval without the account's history must fail: %+v", c)
		}
		r.SignOffHistory = &SignOffCheck{Checked: true, OK: false, Reason: "the account's history holds sign-off 2 on this result, which the sign-offs given leave out"}
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || c.OK || !strings.Contains(c.Reason, "leave out") {
			t.Fatalf("a history that does not match must fail: %+v", c)
		}
		r.SignOffHistory = &SignOffCheck{Checked: true, OK: true, Account: "account-7"}
		r.SignOffs = &SignOffCheck{Checked: true, OK: false, Reason: "bad"}
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || c.OK || !strings.Contains(c.Reason, "do not verify") {
			t.Fatalf("sign-offs that do not verify must fail: %+v", c)
		}
		// Round 59, N16: a history with no head statement cannot show that no
		// later sign-off exists.
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "approve"}
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || c.OK || !strings.Contains(c.Reason, "no head statement") {
			t.Fatalf("a history without a head statement must fail: %+v", c)
		}
		r.SignOffHistory = &SignOffCheck{Checked: true, OK: true, Account: "account-7", CompleteAsOf: "2026-11-12T09:00:00Z"}
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "reject"}
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || c.OK || !strings.Contains(c.Reason, "decision in force is reject") {
			t.Fatalf("a rejection in force must fail: %+v", c)
		}
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "approve"}
		if c := signOffRequirement(r, &artifacts.AuditBundle{}); c == nil || !c.OK || c.Rule != "high-risk" || c.AsOf != "2026-11-12T09:00:00Z" {
			t.Fatalf("an approval in force meets the requirement, as of the head's time: %+v", c)
		}
	}
}

// Round 59, N17: the record itself seals the requirement, so the verifier
// demands sign-off evidence with no policy document given, and a document
// that says the rule requires none contradicts the seal.
func TestASealedSignOffRequirementNeedsNoPolicyDocument(t *testing.T) {
	sealed := &artifacts.AuditBundle{}
	sealed.EPA.AccountPolicyGate = &artifacts.PolicyGate{FiredRuleID: "high-risk", SignOffRequired: true}
	r := &Report{}
	c := signOffRequirement(r, sealed)
	if c == nil || c.OK || !c.Sealed || c.Rule != "high-risk" || !strings.Contains(c.Reason, "pass --signoff") {
		t.Fatalf("a sealed requirement must be checked without the document: %+v", c)
	}
	r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "approve"}
	r.SignOffHistory = &SignOffCheck{Checked: true, OK: true, CompleteAsOf: "2026-11-12T09:00:00Z"}
	if c := signOffRequirement(r, sealed); c == nil || !c.OK {
		t.Fatalf("an approval in force, complete as of the head, meets a sealed requirement: %+v", c)
	}
	r.AccountPolicyGate = &PolicyGateCheck{FiredRuleID: "high-risk", RulesChecked: true, SignOffRequired: false}
	if c := signOffRequirement(r, sealed); c == nil || c.OK || !strings.Contains(c.Reason, "says it does not") {
		t.Fatalf("a document that contradicts the seal must fail: %+v", c)
	}
	if c := signOffRequirement(&Report{}, &artifacts.AuditBundle{}); c != nil {
		t.Fatalf("no seal and no document: no requirement: %+v", c)
	}
}

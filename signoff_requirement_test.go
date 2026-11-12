package main

import (
	"strings"
	"testing"
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
	if c := signOffRequirement(&Report{PolicyGate: PolicyGateCheck{FiredRuleID: "ordinary"}}); c != nil {
		t.Fatalf("a rule that requires no sign-off adds no check: %+v", c)
	}
	for _, account := range []bool{false, true} {
		r := required(account)
		if c := signOffRequirement(r); c == nil || c.OK || !strings.Contains(c.Reason, "pass --signoff") || !strings.Contains(c.Reason, "--signoff-history") {
			t.Fatalf("no sign-offs given must fail and say what to pass: %+v", c)
		}
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "approve"}
		if c := signOffRequirement(r); c == nil || c.OK || !strings.Contains(c.Reason, "--signoff-history") {
			t.Fatalf("an approval without the account's history must fail: %+v", c)
		}
		r.SignOffHistory = &SignOffCheck{Checked: true, OK: false, Reason: "the account's history holds sign-off 2 on this result, which the sign-offs given leave out"}
		if c := signOffRequirement(r); c == nil || c.OK || !strings.Contains(c.Reason, "leave out") {
			t.Fatalf("a history that does not match must fail: %+v", c)
		}
		r.SignOffHistory = &SignOffCheck{Checked: true, OK: true, Account: "account-7"}
		r.SignOffs = &SignOffCheck{Checked: true, OK: false, Reason: "bad"}
		if c := signOffRequirement(r); c == nil || c.OK || !strings.Contains(c.Reason, "do not verify") {
			t.Fatalf("sign-offs that do not verify must fail: %+v", c)
		}
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "reject"}
		if c := signOffRequirement(r); c == nil || c.OK || !strings.Contains(c.Reason, "decision in force is reject") {
			t.Fatalf("a rejection in force must fail: %+v", c)
		}
		r.SignOffs = &SignOffCheck{Checked: true, OK: true, Latest: "approve"}
		if c := signOffRequirement(r); c == nil || !c.OK || c.Rule != "high-risk" {
			t.Fatalf("an approval in force meets the requirement: %+v", c)
		}
	}
}

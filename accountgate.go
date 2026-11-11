package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/psleval"
)

// The account layer (v0.21.0). A record from a key that belongs to an account
// seals the account's number, and, when the account has a policy, that
// policy's decision beside the key's gate: the key's own policy, or, for a key
// with none, Verdifax's built-in policy, which admits every request and keeps
// the code scan. The account's rules run first. A run is admitted only when
// both allow, so an allowed run's record carrying an account decision carries
// an allow, and running the account's rules again (--account-policy) must
// reach it.
//
// The account number is a label Verdifax assigned, not a verified company
// identity. An account policy is the customer's; Verdifax did not write,
// review or approve it.

// accountIDForm is the only form the server assigns.
var accountIDForm = regexp.MustCompile(`^account-[1-9][0-9]{0,18}$`)

// checkAccountID reports an account number the server could not have sealed.
func checkAccountID(id string) error {
	if id == "" || accountIDForm.MatchString(id) {
		return nil
	}
	return fmt.Errorf("the record names account %q, which is not a number Verdifax assigns (account-N)", safePrefix(id))
}

// gateOf reads one sealed policy decision of an allowed run. Only an allow is
// sealed in the EPA: a refused run seals a receipt instead.
func gateOf(pg *artifacts.PolicyGate) PolicyGateCheck {
	return PolicyGateCheck{
		Present:            true,
		PolicyID:           pg.PolicyID,
		PolicyName:         pg.PolicyName,
		PolicyVersion:      pg.PolicyVersion,
		PolicyHash:         pg.PolicyHash,
		FiredRuleID:        pg.FiredRuleID,
		DecisionReasonCode: pg.DecisionReasonCode,
		Source:             pg.Source,
		DocumentHash:       pg.DocumentHash,
		ActivationHash:     pg.ActivationHash,
		Outcome:            string(psleval.EffectAllow),
		inputs:             pg.Inputs,
		identitySealed:     true,
	}
}

// checkAccountGate holds an account decision to what only an account policy
// can be: the customer's own, under a change in the account's chain, on a
// record that names the account.
func checkAccountGate(c PolicyGateCheck, accountID string) PolicyGateCheck {
	fail := func(format string, args ...any) PolicyGateCheck {
		c.DocumentChecked, c.DocumentMatch, c.Reason = true, false, fmt.Sprintf(format, args...)
		return c
	}
	switch {
	case accountID == "":
		return fail("the record seals an account policy decision but names no account")
	case c.Source != artifacts.PolicySourceCustomer:
		return fail("an account policy is the customer's own, and the record names author %q", c.Source)
	case c.ActivationHash == "":
		return fail("the record's account policy decision names no change in the account's policy history")
	case c.Outcome != "" && c.Outcome != string(psleval.EffectAllow) && c.Outcome != string(psleval.EffectDeny):
		return fail("the account policy decision's outcome %q is neither allow nor deny", safePrefix(c.Outcome))
	}
	return c
}

// accountGateOfBundle reads an allowed run's account decision, if it seals one.
func accountGateOfBundle(b *artifacts.AuditBundle) *PolicyGateCheck {
	if b.EPA.AccountPolicyGate == nil {
		return nil
	}
	g := gateOf(b.EPA.AccountPolicyGate)
	g.aiOutputDeclared = b.AivpT4.AiOutputHash != ""
	g.reviewCheck, g.reviewSealed = "record", b.AivpT4.Review != nil
	c := checkAccountGate(g, b.Nrep.AccountID)
	return &c
}

// accountGateOfReceipt reads a refused or halted run's account decision.
// reviewCheck is "review-required-halt" for an AI review halt that names a
// missing required review, else empty.
func accountGateOfReceipt(ctx *artifacts.ReceiptContext, reviewCheck string) *PolicyGateCheck {
	if ctx == nil || ctx.AccountPolicy == nil {
		return nil
	}
	g := policyBindingOf(ctx.AccountPolicy)
	g.aiOutputDeclared = ctx.Request.AiOutputHash != ""
	g.reviewCheck = reviewCheck
	c := checkAccountGate(g, ctx.AccountID)
	return &c
}

// haltedReceiptKinds are receipts of runs the policy gate admitted, which a
// later check then stopped. Every decision such a receipt seals must be an
// allow, or no decision at all when the run stopped before the rules ran.
var haltedReceiptKinds = map[string]bool{
	"ccv_halt_receipt": true, "macc_halt_receipt": true, "aivp_t4_halt_receipt": true, "failure_receipt": true,
}

// admittedDecisionError reports a halted run whose sealed policy refused it.
func admittedDecisionError(kind, label string, c PolicyGateCheck) error {
	if !haltedReceiptKinds[kind] || !c.Present || c.Outcome == "" || c.Outcome == string(psleval.EffectAllow) {
		return nil
	}
	return fmt.Errorf("this %s is of a run the policy gate admitted, and its sealed %s decision is %q, not allow", kind, label, c.Outcome)
}

// applyAccountPolicyDocument is --account-policy: the account's policy text,
// checked as --policy checks the key's.
func applyAccountPolicyDocument(gate *PolicyGateCheck, doc []byte) *PolicyGateCheck {
	if gate == nil {
		return &PolicyGateCheck{DocumentChecked: true,
			Reason: "--account-policy given, but this record seals no account policy decision to compare it with"}
	}
	c := checkPolicyDocument(*gate, doc)
	return &c
}

// readAccountPolicy reads the --account-policy file.
func readAccountPolicy(path string) []byte {
	doc, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --account-policy:", readErr)
		os.Exit(2)
	}
	return doc
}

// loadAccountPolicyHistory is --account-policy-history: the account's chain of
// policy changes, checked as --policy-history checks a key's, whose every
// change must belong to the account the record names.
func loadAccountPolicyHistory(path, accountID string, gate *PolicyGateCheck) *PolicyHistoryCheck {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --account-policy-history:", readErr)
		os.Exit(2)
	}
	c := checkPolicyHistory(data)
	if c.OK && accountID == "" {
		c.OK, c.Reason = false, "--account-policy-history given, but this record names no account"
		return &c
	}
	c = checkAccountChain(c)
	if c.OK && c.Entries[0].ChainID != accountID {
		c.OK, c.Reason = false, fmt.Sprintf("this history belongs to %s, not to the record's account %s", c.Entries[0].ChainID, accountID)
	}
	activation := ""
	if gate != nil {
		activation = gate.ActivationHash
	}
	if c.OK && activation == "" {
		c.OK, c.Reason = false, "--account-policy-history given, but this record seals no account policy decision"
		return &c
	}
	recordInChain(&c, activation)
	return &c
}

// accountFailed reports an account decision or history that did not hold.
func accountFailed(gate *PolicyGateCheck, history *PolicyHistoryCheck) bool {
	return (gate != nil && policyFailed(*gate)) || (history != nil && !history.OK)
}

// accountFailureReason names the first account check that failed.
func accountFailureReason(gate *PolicyGateCheck, history *PolicyHistoryCheck) string {
	if gate != nil && policyFailed(*gate) {
		return gate.Reason
	}
	if history != nil && !history.OK {
		return history.Reason
	}
	return ""
}

// printAccount renders the account lines of the human report.
func printAccount(accountID string, gate *PolicyGateCheck, history *PolicyHistoryCheck) {
	if accountID != "" {
		fmt.Printf("  Account:          %s, a label Verdifax assigned, not a verified company identity\n", accountID)
	}
	if gate != nil {
		printGateLines(*gate, gateLabels{
			gate: "Account policy:", author: "Account author:", document: "Account document:",
			flag: "--account-policy", absent: "this record seals no account policy decision",
		})
	}
	if history != nil {
		printHistoryLines(*history, "Account history:")
	}
}

// applyAccountFlags records --account-policy and --account-policy-history on
// an allowed run's report; either failing fails verification.
func applyAccountFlags(r *Report, policyPath, historyPath string) {
	if policyPath != "" {
		r.AccountPolicyGate = applyAccountPolicyDocument(r.AccountPolicyGate, readAccountPolicy(policyPath))
	}
	if historyPath != "" {
		r.AccountPolicyHistory = loadAccountPolicyHistory(historyPath, r.AccountID, r.AccountPolicyGate)
	}
	if accountFailed(r.AccountPolicyGate, r.AccountPolicyHistory) {
		r.AllPassed = false
		r.VerdictTier = "FAILED"
		r.RecordCoverage = "failed"
	}
}

// applyReceiptAccountFlags is the same for a refused or halted run.
func applyReceiptAccountFlags(r *ReceiptReport, policyPath, historyPath string) {
	if policyPath != "" {
		r.AccountPolicyGate = applyAccountPolicyDocument(r.AccountPolicyGate, readAccountPolicy(policyPath))
	}
	if historyPath != "" {
		r.AccountPolicyHistory = loadAccountPolicyHistory(historyPath, r.AccountID, r.AccountPolicyGate)
	}
	if accountFailed(r.AccountPolicyGate, r.AccountPolicyHistory) {
		r.VerdictTier, r.AllPassed, r.Reason = "FAILED", false, accountFailureReason(r.AccountPolicyGate, r.AccountPolicyHistory)
	}
}

// runAccountHistoryMode checks an account's history file with no record:
// the chain as --policy-history checks it, every change in one account.
func runAccountHistoryMode(path string, asJSON bool) int {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --account-policy-history:", readErr)
		return 2
	}
	c := checkAccountChain(checkPolicyHistory(data))
	if asJSON {
		encoded, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Println("Verdifax account policy history verification")
		printHistoryLines(c, "Account history:")
	}
	if !c.OK {
		return 1
	}
	return 0
}

// checkAccountChain requires every change to belong to one account.
func checkAccountChain(c PolicyHistoryCheck) PolicyHistoryCheck {
	if !c.OK {
		return c
	}
	account := c.Entries[0].ChainID
	if !accountIDForm.MatchString(account) {
		c.OK, c.Reason = false, fmt.Sprintf("change 1 belongs to %q, which is not an account's policy history (account-N)", safePrefix(account))
		return c
	}
	for _, e := range c.Entries {
		if e.ChainID != account {
			c.OK, c.Reason = false, fmt.Sprintf("change %d belongs to %q, not to %s", e.Sequence, safePrefix(e.ChainID), account)
			return c
		}
	}
	return c
}

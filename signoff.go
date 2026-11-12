package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Customer sign-off (v0.22.0). A sign-off is one approver's decision, approve
// or reject, on one exact result, signed with a key the account registered and
// anchored on the public log. It shows that the holder of that key signed the
// decision and Verdifax logged it. It does not show the review was careful,
// the result was right, or who the person is: a key is not an identity.

// SignOffEntry is one sign-off, as the report lists it.
type SignOffEntry struct {
	Sequence    int64  `json:"sequence"`
	Target      string `json:"target"`
	RunID       int64  `json:"run_id"`
	Decision    string `json:"decision"`
	ApproverKey string `json:"approver_key"`
	SignedAt    string `json:"signed_at"`
	RecordedAt  string `json:"recorded_at"`
	LogEntry    string `json:"log_entry,omitempty"`
	Superseded  bool   `json:"superseded,omitempty"`
	// hash is the sign-off's own hash, which compares the sign-offs given
	// for a record with the account's history exactly.
	hash string
}

// SignOffCheck reports the sign-offs given for a record, or an account's whole
// chain of sign-offs.
type SignOffCheck struct {
	Checked bool           `json:"checked"`
	OK      bool           `json:"ok"`
	Entries []SignOffEntry `json:"entries,omitempty"`
	// Latest is the decision in force for the record: the last sign-off on
	// it, which supersedes every earlier one.
	Latest         string `json:"latest_decision,omitempty"`
	LatestApprover string `json:"latest_approver_key,omitempty"`
	// LatestMeaning says what the decision in force states, the same for
	// every kind of result: approve agrees with the result signed, a
	// verdict, a record or the stop a receipt records; reject judges it
	// wrong. A sign-off releases or blocks nothing on its own (R159).
	LatestMeaning  string `json:"latest_meaning,omitempty"`
	ApproverPinned bool   `json:"approver_pinned,omitempty"`
	// Gaps lists the restore gaps the history holds, each sealed and on the
	// public log (round 56, E4).
	Gaps []string `json:"restore_gaps,omitempty"`
	// Account is the account a history belongs to.
	Account string `json:"account,omitempty"`
	// OwnDecision is, when a job's sign-off governs a job's final step, the
	// latest sign-off on the record itself, shown under it (round 59, N19).
	OwnDecision string `json:"own_decision,omitempty"`
	// CompleteAsOf is the public log's time for the head statement that ends
	// a history: the history is complete as of then (round 59, N16).
	CompleteAsOf string `json:"complete_as_of,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// list is the sign-offs read, in chain order.
	list []artifacts.SignOff
}

// signOffSubject is the result a record's sign-offs must name.
type signOffSubject struct {
	account string
	kind    string // record or receipt
	runID   int64
	digest  string
}

// result is the subject in the shared definition's terms.
func (s signOffSubject) result() artifacts.SignOffResult {
	return artifacts.SignOffResult{Kind: s.kind, RunID: s.runID, Digest: s.digest}
}

var reflectSignOffList = reflect.TypeOf([]artifacts.SignOff{})

// readSignOffs reads a strict JSON list of sign-offs.
func readSignOffs(data []byte) ([]artifacts.SignOff, error) {
	if strictErr := artifacts.CheckStrict(data, reflectSignOffList); strictErr != nil {
		return nil, fmt.Errorf("the sign-offs are not plain JSON: %w", strictErr)
	}
	var list []artifacts.SignOff
	if parseErr := json.Unmarshal(data, &list); parseErr != nil {
		return nil, fmt.Errorf("the sign-offs could not be read: %w", parseErr)
	}
	if len(list) == 0 {
		return nil, errors.New("the file holds no sign-offs")
	}
	return list, nil
}

// checkOneSignOff checks a sign-off on its own: its shape, its hash, the
// approver's signature and its public-log entry.
func checkOneSignOff(s *artifacts.SignOff) error {
	if shapeErr := s.Validate(); shapeErr != nil {
		return shapeErr
	}
	if got := s.ComputeHash(); got != s.SignOffHash {
		return fmt.Errorf("its hash recomputes to %s, not %s", truncate(got, 16), truncate(s.SignOffHash, 16))
	}
	pub, _ := base64.StdEncoding.DecodeString(s.ApproverKey)
	sig, _ := base64.StdEncoding.DecodeString(s.Signature)
	if !ed25519.Verify(pub, s.Preimage(), sig) {
		return errors.New("the approver's signature does not verify")
	}
	recorded, clockErr := time.Parse(time.RFC3339Nano, s.RecordedAt)
	if clockErr != nil {
		return fmt.Errorf("recorded_at %q is not an RFC 3339 time", safePrefix(s.RecordedAt))
	}
	return checkChainEntry(s.Anchor, artifacts.SignOffKind, s.SignOffHash, s.LeafHash(), recorded, "recorded_at")
}

func entryOf(s *artifacts.SignOff) SignOffEntry {
	e := SignOffEntry{Sequence: s.Sequence, Target: s.Target.Kind, RunID: s.Target.RunID, Decision: s.Decision,
		ApproverKey: s.ApproverKey, SignedAt: s.SignedAt, RecordedAt: s.RecordedAt, hash: s.SignOffHash}
	if s.Anchor != nil {
		e.LogEntry = s.Anchor.LogEntryID
	}
	return e
}

// checkSignOffs checks the sign-offs given for one record or receipt: each
// must verify on its own, belong to the record's account and name this exact
// result. The latest supersedes the rest.
func checkSignOffs(data []byte, subject signOffSubject) SignOffCheck {
	c := SignOffCheck{Checked: true}
	list, readErr := readSignOffs(data)
	if readErr != nil {
		c.Reason = readErr.Error()
		return c
	}
	if subject.account == "" {
		c.Reason = "--signoff given, but this record names no account, so no approver could sign it off"
		return c
	}
	if subject.digest == "" {
		c.Reason = "--signoff given, but this record has no verified public-log digest for a sign-off to name"
		return c
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Sequence < list[j].Sequence })
	for i := range list {
		s := &list[i]
		if i > 0 && s.Sequence == list[i-1].Sequence {
			c.Reason = fmt.Sprintf("two sign-offs hold sequence %d", s.Sequence)
			return c
		}
		if checkErr := checkOneSignOff(s); checkErr != nil {
			c.Reason = fmt.Sprintf("sign-off %d: %v", s.Sequence, checkErr)
			return c
		}
		if s.ChainID != subject.account {
			c.Reason = fmt.Sprintf("sign-off %d belongs to %s, not to the record's account %s", s.Sequence, s.ChainID, subject.account)
			return c
		}
		if nameErr := namesSubject(s.Target, subject); nameErr != nil {
			c.Reason = fmt.Sprintf("sign-off %d %v", s.Sequence, nameErr)
			return c
		}
	}
	// The decision in force, by the one definition the server, the reports
	// and the SDKs use: on a job's final step the job's decision governs.
	inForce, own := artifacts.DecisionInForce(list, subject.result())
	for i := range list {
		e := entryOf(&list[i])
		e.Superseded = list[i].SignOffHash != inForce.SignOffHash
		c.Entries = append(c.Entries, e)
	}
	c.OK, c.Latest, c.LatestApprover, c.list = true, inForce.Decision, inForce.ApproverKey, list
	c.LatestMeaning = signOffMeaning(inForce.Decision, inForce.Target.Kind)
	if own != nil {
		c.OwnDecision = own.Decision
	}
	return c
}

// signOffMeaning is what a decision states about the result it names. One
// meaning for every kind: approve agrees, reject judges the result wrong.
// Neither releases nor blocks anything on its own.
func signOffMeaning(decision, kind string) string {
	result := "this result"
	switch kind {
	case artifacts.SignOffTargetReceipt:
		result = "the stop this receipt records"
	case artifacts.SignOffTargetJob:
		result = "this job's result"
	case artifacts.SignOffTargetRecord:
		result = "this record's result"
	}
	if decision == artifacts.SignOffApprove {
		return "the approver agrees with " + result
	}
	return "the approver judges " + result + " wrong"
}

// namesSubject reports a target that is not this exact result. A job
// sign-off names the job's final step, so it is checked against that
// step's own record.
func namesSubject(t artifacts.SignOffTarget, subject signOffSubject) error {
	switch {
	case subject.kind == artifacts.SignOffTargetReceipt && t.Kind != artifacts.SignOffTargetReceipt:
		return fmt.Errorf("names a %s, and this is a refused or halted run's receipt", t.Kind)
	case subject.kind == artifacts.SignOffTargetRecord && t.Kind == artifacts.SignOffTargetReceipt:
		return errors.New("names a receipt, and this is a completed run's record")
	case t.RunID != subject.runID:
		return fmt.Errorf("names run %d, not this run %d", t.RunID, subject.runID)
	case t.Digest != subject.digest:
		return fmt.Errorf("names digest %s, not this result's %s", truncate(t.Digest, 16), truncate(subject.digest, 16))
	case !t.NamesResult(subject.result()):
		return fmt.Errorf("is a %s sign-off, which does not name this %s", t.Kind, subject.kind)
	}
	return nil
}

// checkSignOffHistory checks an account's whole chain of sign-offs, oldest
// first: every sign-off on its own, every link, one account throughout. A
// removed, reordered or rewritten sign-off fails.
func checkSignOffHistory(data []byte) SignOffCheck {
	c := SignOffCheck{Checked: true}
	items, readErr := readChainItems(data, reflect.TypeOf(artifacts.SignOff{}))
	if readErr != nil {
		c.Reason = "the sign-off history: " + readErr.Error()
		return c
	}
	var list []artifacts.SignOff
	previous := artifacts.NoPreviousSignOff
	next := int64(1)
	// The account each skip's event belongs to: one account throughout.
	var skipAccounts []string
	var head *artifacts.SignOffHead
	for i, item := range items {
		if item.head != nil {
			if i != len(items)-1 {
				c.Reason = "the history's head statement is not its last entry"
				return c
			}
			head = item.head
			continue
		}
		if item.isSkip() {
			after, line, gapErr := item.checkSkip(artifacts.GapChainSignOffs, 0, next)
			if gapErr != nil {
				c.Reason = fmt.Sprintf("after sign-off %d: %v", len(list), gapErr)
				return c
			}
			next = after
			c.Gaps = append(c.Gaps, line)
			skipAccounts = append(skipAccounts, item.skipAccount())
			continue
		}
		var so artifacts.SignOff
		if err := json.Unmarshal(item.raw, &so); err != nil {
			c.Reason = fmt.Sprintf("sign-off %d could not be read: %v", len(list)+1, err)
			return c
		}
		list = append(list, so)
		i := len(list) - 1
		s := &list[i]
		switch {
		case s.Sequence != next:
			c.Reason = fmt.Sprintf("sign-off %d: sequence is %d, so a sign-off is missing or out of order", i+1, s.Sequence)
			return c
		case s.PreviousSignOffHash != previous:
			c.Reason = fmt.Sprintf("sign-off %d does not link to the sign-off before it, so one was removed or replaced", i+1)
			return c
		case i > 0 && s.ChainID != list[0].ChainID:
			c.Reason = fmt.Sprintf("sign-off %d belongs to %s, not to %s", i+1, s.ChainID, list[0].ChainID)
			return c
		}
		if checkErr := checkOneSignOff(s); checkErr != nil {
			c.Reason = fmt.Sprintf("sign-off %d: %v", i+1, checkErr)
			return c
		}
		c.Entries = append(c.Entries, entryOf(s))
		previous = s.SignOffHash
		next++
	}
	if len(list) == 0 {
		c.Reason = "the sign-off history holds no sign-offs"
		return c
	}
	for _, account := range skipAccounts {
		if account != list[0].ChainID {
			c.Reason = fmt.Sprintf("a record that skips places belongs to %s, not to %s", account, list[0].ChainID)
			return c
		}
	}
	// A later sign-off on the same result supersedes the earlier one.
	last := map[string]int{}
	for i, e := range c.Entries {
		last[fmt.Sprintf("%s/%d", e.Target, e.RunID)] = i
	}
	for i := range c.Entries {
		c.Entries[i].Superseded = last[fmt.Sprintf("%s/%d", c.Entries[i].Target, c.Entries[i].RunID)] != i
	}
	c.OK, c.Account, c.list = true, list[0].ChainID, list
	if head != nil {
		if headErr := checkSignOffHead(head, list[0].ChainID, next-1, previous); headErr != nil {
			c.OK, c.Reason = false, headErr.Error()
			return c
		}
		c.CompleteAsOf = time.Unix(head.Anchor.IntegratedTime, 0).UTC().Format(time.RFC3339)
	}
	return c
}

// checkSignOffHead checks the head statement that ends a history: Verdifax's
// statement on the public log of the chain's highest place and newest
// sign-off. A history shorter than its head, a head of another account, or a
// head not on the public log fails.
func checkSignOffHead(h *artifacts.SignOffHead, account string, highest int64, newest string) error {
	if err := checkSealedEntry(h.Validate(), h.ComputeHash(), h.HeadStatementHash, h.StatedAt, "stated_at",
		h.Anchor, artifacts.SignOffHeadKind, h.LeafHash()); err != nil {
		return fmt.Errorf("the history's head statement: %w", err)
	}
	switch {
	case h.ChainID != account:
		return fmt.Errorf("the history's head statement is %s's, not %s's", h.ChainID, account)
	case h.Sequence != highest || h.HeadHash != newest:
		return fmt.Errorf("the history ends at place %d, and Verdifax's head statement of %s says the chain's highest place is %d, so sign-offs were left out of the end", highest, h.StatedAt, h.Sequence)
	}
	return nil
}

// pinApprover is --approver-key: the decision in force must be that key's.
func pinApprover(c *SignOffCheck, keyFile string) {
	if !c.OK {
		return
	}
	raw, readErr := os.ReadFile(keyFile)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --approver-key:", readErr)
		os.Exit(2)
	}
	want := strings.TrimSpace(string(raw))
	if want != c.LatestApprover {
		c.OK, c.Reason = false, fmt.Sprintf("the decision in force was signed by %s, not by the approver key given", truncate(c.LatestApprover, 12))
		return
	}
	c.ApproverPinned = true
}

// readFlagFile reads a file named by a flag, or exits 2.
func readFlagFile(flag, path string) []byte {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "verdifax-verify: read --%s: %v\n", flag, readErr)
		os.Exit(2)
	}
	return data
}

// signOffChecks runs --signoff, --approver-key and --signoff-history for one
// subject.
func signOffChecks(subject signOffSubject, signOffPath, approverPath, historyPath string) (*SignOffCheck, *SignOffCheck) {
	var given, history *SignOffCheck
	if signOffPath != "" {
		c := checkSignOffs(readFlagFile("signoff", signOffPath), subject)
		if approverPath != "" {
			pinApprover(&c, approverPath)
		}
		given = &c
	} else if approverPath != "" {
		given = &SignOffCheck{Checked: true, Reason: "--approver-key given without --signoff"}
	}
	if historyPath != "" {
		c := checkSignOffHistory(readFlagFile("signoff-history", historyPath))
		if c.OK && given != nil && given.OK {
			if problem := historyDisagrees(*given, c, subject); problem != "" {
				c.OK, c.Reason = false, problem
			}
		}
		history = &c
	}
	return given, history
}

// historyDisagrees compares the sign-offs given for one result with the
// account's history: the history must be the record's account's, hold every
// sign-off given, and the sign-offs given must hold every sign-off the
// history has on this result. Otherwise a later decision left out of the
// sign-offs given would make an earlier one read as the decision in force.
func historyDisagrees(given, history SignOffCheck, subject signOffSubject) string {
	if history.Account != subject.account {
		return fmt.Sprintf("the sign-off history given belongs to %s, not to the record's account %s", history.Account, subject.account)
	}
	held, gave := map[string]bool{}, map[string]bool{}
	for _, e := range history.Entries {
		held[e.hash] = true
	}
	for _, e := range given.Entries {
		gave[e.hash] = true
		if !held[e.hash] {
			return fmt.Sprintf("sign-off %d is not in the account's history given", e.Sequence)
		}
	}
	for _, e := range history.list {
		if e.Target.NamesResult(subject.result()) && !gave[e.SignOffHash] {
			return fmt.Sprintf("the account's history holds sign-off %d on this result, a %s sign-off, which the sign-offs given leave out, so they do not show the decision in force", e.Sequence, e.Target.Kind)
		}
	}
	return ""
}

// signOffFailed reports a sign-off check that ran and did not hold.
func signOffFailed(checks ...*SignOffCheck) (bool, string) {
	for _, c := range checks {
		if c != nil && !c.OK {
			return true, c.Reason
		}
	}
	return false, ""
}

// SignOffRequirementCheck is the check of a sign-off the policy rule that
// allowed a run requires (round 58, B7).
type SignOffRequirementCheck struct {
	Rule string `json:"rule"`
	// Sealed says the record itself seals the requirement (round 59, N17);
	// otherwise only the policy document given shows it.
	Sealed bool `json:"sealed,omitempty"`
	// AsOf is when the history given was complete, by its head statement.
	AsOf   string `json:"as_of,omitempty"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// signOffRequirement checks a run whose allowing rule requires a person's
// sign-off: it holds only when --signoff shows an approval in force on this
// record. A sign-off releases or blocks nothing on its own (R159); this
// checks that the control the policy names took place.
func signOffRequirement(r *Report, b *artifacts.AuditBundle) *SignOffRequirementCheck {
	rule, sealed := "", false
	// The record's own seal (round 59, N17), then the documents given.
	for _, g := range []*artifacts.PolicyGate{b.EPA.PolicyGate, b.EPA.AccountPolicyGate} {
		if g != nil && g.SignOffRequired && rule == "" {
			rule, sealed = g.FiredRuleID, true
		}
	}
	switch {
	case rule != "":
	case r.PolicyGate.SignOffRequired:
		rule = r.PolicyGate.FiredRuleID
	case r.AccountPolicyGate != nil && r.AccountPolicyGate.SignOffRequired:
		rule = r.AccountPolicyGate.FiredRuleID
	default:
		return nil
	}
	c := &SignOffRequirementCheck{Rule: rule, Sealed: sealed}
	// A document given that reads the rules again must agree with the seal.
	for _, pair := range []struct {
		sealed *artifacts.PolicyGate
		check  *PolicyGateCheck
	}{{b.EPA.PolicyGate, &r.PolicyGate}, {b.EPA.AccountPolicyGate, r.AccountPolicyGate}} {
		if pair.sealed != nil && pair.check != nil && pair.check.RulesChecked && pair.check.Reason == "" &&
			pair.sealed.SignOffRequired && !pair.check.SignOffRequired {
			c.Reason = fmt.Sprintf("the record seals that rule %q requires a person's sign-off, and the policy document given says it does not", rule)
			return c
		}
	}
	switch {
	case r.SignOffs == nil || r.SignOffHistory == nil:
		c.Reason = fmt.Sprintf("rule %q requires a person's sign-off on this result; pass --signoff (GET /runs/{id}/signoffs) and --signoff-history (the account's whole chain, GET /account/signoffs/history) so that a later decision cannot be left out", rule)
	case !r.SignOffs.OK:
		c.Reason = fmt.Sprintf("rule %q requires a person's sign-off, and the sign-offs given do not verify", rule)
	case !r.SignOffHistory.OK:
		c.Reason = fmt.Sprintf("rule %q requires a person's sign-off, and the account's sign-off history given does not verify or does not match the sign-offs given: %s", rule, r.SignOffHistory.Reason)
	case r.SignOffHistory.CompleteAsOf == "":
		c.Reason = fmt.Sprintf("rule %q requires a person's sign-off, and the history given ends with no head statement, so it cannot show that no later sign-off exists; fetch the history again from GET /account/signoffs/history, which ends with one from the server release that came with verifier v0.31.0", rule)
	case r.SignOffs.Latest != artifacts.SignOffApprove:
		latest := r.SignOffs.Latest
		if latest == "" {
			latest = "none"
		}
		c.Reason = fmt.Sprintf("rule %q requires an approving sign-off on this result, and the decision in force is %s", rule, latest)
	default:
		c.OK, c.AsOf = true, r.SignOffHistory.CompleteAsOf
	}
	return c
}

func printSignOffRequirement(c *SignOffRequirementCheck) {
	if c == nil {
		return
	}
	if c.OK {
		fmt.Printf("  %-18s✓ rule %q requires a person's sign-off; an approval is in force as of %s, matched with the account's history\n", "Sign-off rule:", c.Rule, c.AsOf)
		return
	}
	fmt.Printf("  %-18s✗ FAILED · %s\n", "Sign-off rule:", c.Reason)
}

// applySignOffFlags records the sign-off checks on an allowed run's report,
// and the sign-off its allowing rule requires, if any (round 58, B7).
func applySignOffFlags(r *Report, b *artifacts.AuditBundle, signOffPath, approverPath, historyPath string) {
	defer func() {
		if r.SignOffRequirement = signOffRequirement(r, b); r.SignOffRequirement != nil && !r.SignOffRequirement.OK {
			r.AllPassed, r.VerdictTier, r.RecordCoverage = false, "FAILED", "failed"
		}
	}()
	if signOffPath == "" && approverPath == "" && historyPath == "" {
		return
	}
	subject := signOffSubject{account: b.Nrep.AccountID, kind: artifacts.SignOffTargetRecord, runID: int64(b.RunID)}
	if r.BundleAnchor.Match && b.BundleAnchor != nil {
		subject.digest = b.BundleAnchor.AnchoredDigest
	}
	r.SignOffs, r.SignOffHistory = signOffChecks(subject, signOffPath, approverPath, historyPath)
	if failed, _ := signOffFailed(r.SignOffs, r.SignOffHistory); failed {
		r.AllPassed, r.VerdictTier, r.RecordCoverage = false, "FAILED", "failed"
	}
}

// applyReceiptSignOffFlags is the same for a refused or halted run.
func applyReceiptSignOffFlags(r *ReceiptReport, d *artifacts.ReceiptDocument, signOffPath, approverPath, historyPath string) {
	if signOffPath == "" && approverPath == "" && historyPath == "" {
		return
	}
	subject := signOffSubject{kind: artifacts.SignOffTargetReceipt, runID: d.RunID}
	if d.ReceiptContext != nil {
		subject.account = d.ReceiptContext.AccountID
	}
	if r.HashOK {
		subject.digest = r.ReceiptHash
	}
	r.SignOffs, r.SignOffHistory = signOffChecks(subject, signOffPath, approverPath, historyPath)
	if failed, reason := signOffFailed(r.SignOffs, r.SignOffHistory); failed {
		r.VerdictTier, r.AllPassed, r.Reason = "FAILED", false, reason
	}
}

// runSignOffHistoryMode checks an account's sign-off history with no record.
func runSignOffHistoryMode(path string, asJSON bool) int {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --signoff-history:", readErr)
		return 2
	}
	c := checkSignOffHistory(data)
	if asJSON {
		encoded, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Println("Verdifax sign-off history verification")
		printSignOffs(nil, &c)
	}
	if !c.OK {
		return 1
	}
	return 0
}

// printSignOffs renders the sign-off lines of the human report.
func printSignOffs(given, history *SignOffCheck) {
	if given != nil {
		switch {
		case !given.OK:
			fmt.Printf("  %-18s✗ FAILED · %s\n", "Sign-off:", given.Reason)
		default:
			pinned := ""
			if given.ApproverPinned {
				pinned = ", the approver key given"
			}
			fmt.Printf("  %-18s%s by approver key %s%s, on the public log\n", "Sign-off:", given.Latest, truncate(given.LatestApprover, 12), pinned)
			fmt.Printf("  %-18s%s; it releases or blocks nothing on its own\n", "Meaning:", given.LatestMeaning)
			if given.OwnDecision != "" {
				fmt.Printf("  %-18sthe job's sign-off governs this final step; the record's own latest sign-off is %s\n", "Job:", given.OwnDecision)
			}
			for _, e := range given.Entries {
				state := ""
				if e.Superseded {
					state = ", superseded"
				}
				fmt.Printf("    %d. %s  %s %s%s\n", e.Sequence, e.RecordedAt, e.Decision, e.Target, state)
			}
			fmt.Println("                    A sign-off shows a registered approver key signed this decision; not that the review was careful, the result right, or who the person is")
		}
	}
	if history != nil {
		if !history.OK {
			fmt.Printf("  %-18s✗ FAILED · %s\n", "Sign-off history:", history.Reason)
			return
		}
		fmt.Printf("  %-18s%d sign-off(s), each linked, on the public log\n", "Sign-off history:", len(history.Entries))
		if history.CompleteAsOf != "" {
			fmt.Printf("  %-18sthe account's sign-offs are complete as of %s, by Verdifax's head statement on the public log\n", "Complete:", history.CompleteAsOf)
		} else {
			fmt.Printf("  %-18sthis covers the sign-offs supplied, with no head statement; a later sign-off may exist\n", "Complete:")
		}
		for _, g := range history.Gaps {
			fmt.Printf("  %-18s%s\n", "Restore gap:", g)
		}
	}
}

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
	ApproverPinned bool   `json:"approver_pinned,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// signOffSubject is the result a record's sign-offs must name.
type signOffSubject struct {
	account string
	kind    string // record or receipt
	runID   int64
	digest  string
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
		ApproverKey: s.ApproverKey, SignedAt: s.SignedAt, RecordedAt: s.RecordedAt}
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
		e := entryOf(s)
		e.Superseded = i < len(list)-1
		c.Entries = append(c.Entries, e)
	}
	last := list[len(list)-1]
	c.OK, c.Latest, c.LatestApprover = true, last.Decision, last.ApproverKey
	return c
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
	}
	return nil
}

// checkSignOffHistory checks an account's whole chain of sign-offs, oldest
// first: every sign-off on its own, every link, one account throughout. A
// removed, reordered or rewritten sign-off fails.
func checkSignOffHistory(data []byte) SignOffCheck {
	c := SignOffCheck{Checked: true}
	list, readErr := readSignOffs(data)
	if readErr != nil {
		c.Reason = readErr.Error()
		return c
	}
	previous := artifacts.NoPreviousSignOff
	for i := range list {
		s := &list[i]
		switch {
		case s.Sequence != int64(i+1):
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
	}
	// A later sign-off on the same result supersedes the earlier one.
	last := map[string]int{}
	for i, e := range c.Entries {
		last[fmt.Sprintf("%s/%d", e.Target, e.RunID)] = i
	}
	for i := range c.Entries {
		c.Entries[i].Superseded = last[fmt.Sprintf("%s/%d", c.Entries[i].Target, c.Entries[i].RunID)] != i
	}
	c.OK = true
	return c
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
			if missing := missingFromHistory(*given, c); missing != "" {
				c.OK, c.Reason = false, missing
			}
		}
		history = &c
	}
	return given, history
}

// missingFromHistory reports a sign-off given for the record that the
// account's history does not hold.
func missingFromHistory(given, history SignOffCheck) string {
	held := map[int64]bool{}
	for _, e := range history.Entries {
		held[e.Sequence] = true
	}
	for _, e := range given.Entries {
		if !held[e.Sequence] {
			return fmt.Sprintf("sign-off %d is not in the account's history given", e.Sequence)
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

// applySignOffFlags records the sign-off checks on an allowed run's report.
func applySignOffFlags(r *Report, b *artifacts.AuditBundle, signOffPath, approverPath, historyPath string) {
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
	}
}

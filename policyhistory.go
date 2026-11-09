package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// PolicyHistoryEntry is one change, as the report lists it.
type PolicyHistoryEntry struct {
	Sequence       int64  `json:"sequence"`
	ChainID        string `json:"chain_id,omitempty"`
	PolicyID       string `json:"policy_id"`
	PolicyVersion  string `json:"policy_version"`
	PolicyHash     string `json:"policy_hash"`
	ActivatedAt    string `json:"activated_at"`
	ActivationHash string `json:"activation_hash"`
	SignedBy       string `json:"signed_by,omitempty"`
	LogEntry       string `json:"log_entry,omitempty"`
}

// PolicyHistoryCheck reports a chain of policy changes. A complete chain shows
// no change was removed from the part supplied. It cannot show that nothing
// came after the last record: a later record's activation_hash shows that.
type PolicyHistoryCheck struct {
	Checked       bool                 `json:"checked"`
	OK            bool                 `json:"ok"`
	Entries       []PolicyHistoryEntry `json:"entries,omitempty"`
	RecordInChain bool                 `json:"record_in_chain,omitempty"`
	Reason        string               `json:"reason,omitempty"`
}

var reflectActivationList = reflect.TypeOf([]artifacts.PolicyActivation{})

// checkPolicyHistory reads a JSON list of activation records, oldest first, and
// checks every one and every link.
func checkPolicyHistory(data []byte) PolicyHistoryCheck {
	c := PolicyHistoryCheck{Checked: true}
	var chain []artifacts.PolicyActivation
	if strictErr := artifacts.CheckStrict(data, reflectActivationList); strictErr != nil {
		c.Reason = fmt.Sprintf("the policy history is not plain JSON: %v", strictErr)
		return c
	}
	if parseErr := json.Unmarshal(data, &chain); parseErr != nil {
		c.Reason = fmt.Sprintf("the policy history could not be read: %v", parseErr)
		return c
	}
	if len(chain) == 0 {
		c.Reason = "the policy history holds no changes"
		return c
	}
	previous := artifacts.NoPreviousActivation
	var previousAt time.Time
	for i := range chain {
		a := &chain[i]
		at, entryErr := checkActivation(a, int64(i+1), previous, previousAt)
		if entryErr != nil {
			c.Reason = fmt.Sprintf("change %d: %v", i+1, entryErr)
			return c
		}
		entry := PolicyHistoryEntry{Sequence: a.Sequence, ChainID: a.ChainID, PolicyID: a.PolicyID, PolicyVersion: a.PolicyVersion, PolicyHash: a.PolicyHash,
			ActivatedAt: a.ActivatedAt, ActivationHash: a.ActivationHash, LogEntry: a.Anchor.LogEntryID}
		if a.Signature != nil {
			entry.SignedBy = a.Signature.PublicKey
		}
		c.Entries = append(c.Entries, entry)
		previous, previousAt = a.ActivationHash, at
	}
	c.OK = true
	return c
}

// checkActivation checks one record and its link to the one before.
func checkActivation(a *artifacts.PolicyActivation, sequence int64, previous string, previousAt time.Time) (time.Time, error) {
	if shapeErr := a.Validate(); shapeErr != nil {
		return time.Time{}, shapeErr
	}
	if a.Sequence != sequence {
		return time.Time{}, fmt.Errorf("sequence is %d, so a change is missing or out of order", a.Sequence)
	}
	if a.PreviousActivationHash != previous {
		return time.Time{}, errors.New("it does not link to the change before it, so a change was removed or replaced")
	}
	if got := a.ComputeHash(); got != a.ActivationHash {
		return time.Time{}, fmt.Errorf("its hash recomputes to %s, not %s", truncate(got, 16), truncate(a.ActivationHash, 16))
	}
	at, clockErr := time.Parse(time.RFC3339Nano, a.ActivatedAt)
	if clockErr != nil {
		return time.Time{}, fmt.Errorf("activated_at %q is not an RFC 3339 time", safePrefix(a.ActivatedAt))
	}
	if at.Before(previousAt) {
		return time.Time{}, errors.New("it is dated before the change it follows")
	}
	if signErr := checkActivationSignature(a); signErr != nil {
		return time.Time{}, signErr
	}
	return at, checkActivationEntry(a, at)
}

// checkActivationSignature checks the customer's approval, when there is one.
func checkActivationSignature(a *artifacts.PolicyActivation) error {
	s := a.Signature
	if s == nil {
		return nil
	}
	pub, keyErr := base64.StdEncoding.DecodeString(s.PublicKey)
	sig, sigErr := base64.StdEncoding.DecodeString(s.Signature)
	if keyErr != nil || sigErr != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return errors.New("its signature is not a base64 Ed25519 key and signature")
	}
	preimage := artifacts.PolicyActivationPreimage(a.ChainID, a.DocumentHash, a.PreviousActivationHash, s.SignedAt, s.Nonce)
	if !ed25519.Verify(pub, preimage, sig) {
		return errors.New("its signature does not verify")
	}
	return nil
}

// checkActivationEntry checks the public-log entry as a receipt's is checked.
func checkActivationEntry(a *artifacts.PolicyActivation, at time.Time) error {
	return checkChainEntry(a.Anchor, artifacts.PolicyActivationKind, a.ActivationHash, a.LeafHash(), at, "activated_at")
}

// checkChainEntry checks the public-log entry of a record in a chain, a
// policy change or a sign-off, as a receipt's entry is checked: it binds this
// record's kind, hash and leaf, verifies against the log, was made by a pinned
// Verdifax key in its accepted period, and inside the anchoring window after
// the record's own time.
// errNoLogEntry is a record that is sound in every other way and carries no
// public-log entry. Alone it fails; in a signal feed a later event's entry
// can commit it (checkSignalFeed).
var errNoLogEntry = errors.New("it carries no public-log entry")

func checkChainEntry(entry *artifacts.ReceiptAnchor, kind, hash, leaf string, at time.Time, clock string) error {
	if entry == nil {
		return errNoLogEntry
	}
	if entry.Backend != "rekor" {
		return fmt.Errorf("its entry's backend is %q, not the public log", entry.Backend)
	}
	if entry.ReceiptKind != kind || entry.ReceiptHash != hash || !strings.EqualFold(entry.LeafHashHex, leaf) {
		return errors.New("its public-log entry does not bind this record")
	}
	verifyErr := rekorAnchorVerifier(rekorverify.AnchorInput{
		LeafHashHex: entry.LeafHashHex, EntryBody: entry.EntryBody, LogIndex: entry.LogIndex,
		TreeSize: entry.TreeSize, RootHashHex: entry.RootHashHex, InclusionPath: entry.InclusionPath,
		Checkpoint: entry.Checkpoint, LogID: entry.LogID, LogEntryID: entry.LogEntryID,
		IntegratedTime: entry.IntegratedTime, SignedEntryTimestamp: entry.SignedEntryTimestamp,
	})
	if verifyErr != nil {
		return fmt.Errorf("its public-log entry does not verify: %w", verifyErr)
	}
	signer, signerErr := entrySignerOf(entry.EntryBody)
	if signerErr != nil {
		return fmt.Errorf("its public-log entry has no valid signer: %w", signerErr)
	}
	key, pinned := pinnedEntrySigners[signer]
	if !pinned {
		return fmt.Errorf("its entry was logged by key %s, not a published Verdifax log-signing key", truncate(signer, 16))
	}
	if !signerAcceptsAt(key, entry.IntegratedTime) {
		return fmt.Errorf("its entry was logged outside the period in which %s is accepted", key.Name)
	}
	gap := float64(entry.IntegratedTime) - float64(at.UnixNano())/1e9
	if gap < -anchoringClockSkew.Seconds() || gap > float64(artifacts.ReceiptAnchoringWindowSeconds) {
		return fmt.Errorf("its entry was logged outside the %d-second window after %s", artifacts.ReceiptAnchoringWindowSeconds, clock)
	}
	return nil
}

// loadPolicyHistory checks a history file against the change a run names.
func loadPolicyHistory(path, activationHash string) *PolicyHistoryCheck {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --policy-history:", readErr)
		os.Exit(2)
	}
	c := checkPolicyHistory(data)
	recordInChain(&c, activationHash)
	return &c
}

// recordInChain reports whether the change a run names is in the chain.
func recordInChain(c *PolicyHistoryCheck, activationHash string) {
	if !c.OK {
		return
	}
	if activationHash == "" {
		c.OK = false
		c.Reason = "--policy-history given, but this record names no policy change"
		return
	}
	for _, e := range c.Entries {
		if e.ActivationHash == activationHash {
			c.RecordInChain = true
			return
		}
	}
	c.OK = false
	c.Reason = "the record names a policy change that is not in this history"
}

func printPolicyHistory(c PolicyHistoryCheck) { printHistoryLines(c, "Policy history:") }

// printHistoryLines renders one chain of policy changes under its label.
func printHistoryLines(c PolicyHistoryCheck, label string) {
	if !c.OK {
		fmt.Printf("  %-18s✗ FAILED · %s\n", label, c.Reason)
		return
	}
	fmt.Printf("  %-18s%d change(s), each linked, on the public log\n", label, len(c.Entries))
	for _, e := range c.Entries {
		signed := "not signed"
		if e.SignedBy != "" {
			signed = "signed by " + truncate(e.SignedBy, 12)
		}
		fmt.Printf("    %d. %s  %s version %s, policy hash %s, %s\n", e.Sequence, e.ActivatedAt, e.PolicyID, e.PolicyVersion, safePrefix(e.PolicyHash), signed)
	}
	if c.RecordInChain {
		fmt.Println("                    The record's policy change is in this history")
	}
	fmt.Println("                    This covers the changes supplied; a later record shows whether more followed")
}

// runPolicyHistoryMode checks a history file with no record.
func runPolicyHistoryMode(path string, asJSON bool) int {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --policy-history:", readErr)
		return 2
	}
	c := checkPolicyHistory(data)
	if asJSON {
		encoded, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Println("Verdifax policy history verification")
		printPolicyHistory(c)
	}
	if !c.OK {
		return 1
	}
	return 0
}

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
	"github.com/Verdifax/verdifax-verify/internal/pslbuiltin"
)

// TestBuiltInVersionsHashHere holds every built-in policy text to the policy
// hash its records seal, with this verifier's own hash code. The server holds
// the same files to its code, so both reach one value.
func TestBuiltInVersionsHashHere(t *testing.T) {
	all, readErr := pslbuiltin.All()
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, v := range all {
		got, hashErr := policyhash.FromDocument(v.Document)
		if hashErr != nil || got.PolicyHash != v.PolicyHash {
			t.Fatalf("%s: %s (%v), listed as %s", v.File, got.PolicyHash, hashErr, v.PolicyHash)
		}
	}
}

// builtInRecord reads a real allowed run the server sealed under its built-in
// policy (written by TestDumpPolicyRecords in the server's tests).
func builtInRecord(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	data, readErr := os.ReadFile("testdata/policy-gate/builtin-allowed.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	b, decodeErr := decodeBundle(data)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	return b
}

// A real built-in record is held to the text this verifier carries, and its
// rules are run again with no --policy file.
func TestARealBuiltInRecordIsRunAgain(t *testing.T) {
	r := verify(builtInRecord(t))
	c := r.PolicyGate
	if !c.DocumentChecked || !c.DocumentMatch || !c.RulesChecked || c.BuiltInFile != "verdifax-default-baseline-permit-1.0.0.json" {
		t.Fatalf("%+v", c)
	}
	if author := policyAuthor(c); !strings.HasPrefix(author, "Verdifax's built-in policy") {
		t.Fatal(author)
	}
}

// A real code-scan refusal seals the rules' own decision, which runs again.
func TestARealBuiltInRefusalIsRunAgain(t *testing.T) {
	data, readErr := os.ReadFile("testdata/policy-gate/builtin-refused.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var d artifacts.ReceiptDocument
	if parseErr := json.Unmarshal(data, &d); parseErr != nil || d.ReceiptContext == nil {
		t.Fatalf("%v", parseErr)
	}
	c := checkBuiltIn(policyBindingOf(d.ReceiptContext.Policy))
	if !c.DocumentMatch || !c.RulesChecked || c.Outcome != "allow" || c.FiredRuleID != "baseline-permit" {
		t.Fatalf("%+v", c)
	}
}

// Each of these names Verdifax as the author and must not pass: the claim is
// held to the text, not taken on trust.
func TestABuiltInClaimThatDoesNotHoldFails(t *testing.T) {
	for name, change := range map[string]func(*PolicyGateCheck){
		"an unknown text":     func(c *PolicyGateCheck) { c.DocumentHash = strings.Repeat("0", 64) },
		"a change record":     func(c *PolicyGateCheck) { c.ActivationHash = strings.Repeat("1", 64) },
		"another rule":        func(c *PolicyGateCheck) { c.FiredRuleID = "default" },
		"another outcome":     func(c *PolicyGateCheck) { c.Outcome = "deny" },
		"another policy hash": func(c *PolicyGateCheck) { c.PolicyHash = strings.Repeat("2", 64) },
		"another policy name": func(c *PolicyGateCheck) { c.PolicyName = "Verdifax Approved Policy" },
		"an unknown author":   func(c *PolicyGateCheck) { c.Source = "auditor" },
		"another version":     func(c *PolicyGateCheck) { c.PolicyVersion = "2.0.0" },
		"another policy id":   func(c *PolicyGateCheck) { c.PolicyID = "verdifax-default-allow-all" },
	} {
		t.Run(name, func(t *testing.T) {
			c := policyGateOf(builtInRecord(t))
			change(&c)
			if got := checkBuiltIn(c); !policyFailed(got) || got.Reason == "" {
				t.Fatalf("passed: %+v", got)
			}
		})
	}
}

// An earlier record names no author. It reads as built-in only when its policy
// hash is a built-in version, and in neither case is it failed.
func TestAnEarlierRecordIsNamedByItsPolicyHash(t *testing.T) {
	for _, v := range []struct{ hash, file string }{
		{"1a090975c0515a14296a0e68bb6840c5de4d76465369c50022e390b3da1e25d0", "verdifax-default-baseline-permit-1.0.0.json"},
		{"0f7c55ca7884039111adc67c9c19f1572c8b48cbdfa50601585eb9acd9f5f042", "verdifax-default-allow-all-1.0.0.json"},
		{"879651939988f228aea8b75b38c89f49a4895b60f3858b37973d9c03a93cb365", ""},
	} {
		c := checkBuiltIn(PolicyGateCheck{Present: true, PolicyHash: v.hash})
		if c.BuiltInFile != v.file || policyFailed(c) {
			t.Fatalf("%s: %+v", v.hash, c)
		}
		author := policyAuthor(c)
		if v.file == "" && strings.Contains(author, "is Verdifax's") {
			t.Fatalf("a test policy reads as Verdifax's: %s", author)
		}
		if !strings.HasPrefix(author, "not recorded") {
			t.Fatal(author)
		}
	}
}

// anchoredBuiltInRefusal is the real built-in refusal, sealed as production
// seals one (anchor_required set, its hash recomputed) and logged on the test
// log with its receipt context, as an anchored receipt from the live API is.
func anchoredBuiltInRefusal(t *testing.T, l *testLog, edit func(*artifacts.ReceiptDocument)) *artifacts.ReceiptDocument {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/policy-gate/builtin-refused.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	d, decodeErr := artifacts.DecodeReceiptStrict(raw)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if edit != nil {
		edit(d)
	}
	r := d.DenyReceipt
	r.AnchorRequired = true
	hash, hashErr := artifacts.BuildDenyReceiptHash(r)
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	r.Hash = hash
	clock, clockErr := time.Parse(time.RFC3339Nano, r.DenyClock)
	if clockErr != nil {
		t.Fatal(clockErr)
	}
	l.integratedTime = clock.Add(2 * time.Second).Unix()
	e := l.entry(t, strings.Repeat("0", 64), artifacts.ComputeReceiptLeafHashV3("deny_receipt", r.EnvelopeID, r.Hash, d.RunID, d.ReceiptContext.Hash()))
	d.ReceiptAnchor = &artifacts.ReceiptAnchor{Kind: artifacts.ReceiptAnchorKindV3, ReceiptKind: "deny_receipt", ReceiptHash: r.Hash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex, LogIndex: e.LogIndex, TreeSize: e.TreeSize,
		RootHashHex: e.RootHashHex, InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime, EntryBody: e.EntryBody}
	return d
}

// An anchored built-in refusal verifies, and its rules run again with no
// --policy file. The same receipt, logged as faithfully but naming a built-in
// text this verifier does not carry, fails as a whole.
func TestAnAnchoredBuiltInRefusalIsHeldToItsText(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	r := mustReceiptTier(t, "anchored built-in refusal", "VERIFIED_ANCHORED", anchoredBuiltInRefusal(t, l, nil))
	if !r.PolicyGate.RulesChecked || r.PolicyGate.BuiltInFile == "" {
		t.Fatalf("%+v", r.PolicyGate)
	}
	unknown := anchoredBuiltInRefusal(t, l, func(d *artifacts.ReceiptDocument) {
		d.ReceiptContext.Policy.DocumentHash = strings.Repeat("0", 64)
	})
	if got := mustReceiptTier(t, "unknown built-in text", "FAILED", unknown); !strings.Contains(got.Reason, "does not carry") {
		t.Fatal(got.Reason)
	}
}

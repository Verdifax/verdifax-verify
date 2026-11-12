package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// accountGate is what an account policy seals on an allowed run: rerunPolicy,
// the customer's, under a change in the account's history.
func accountGate(t *testing.T, activation string) *artifacts.PolicyGate {
	t.Helper()
	r, hashErr := policyhash.FromDocument([]byte(accountPolicy))
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	sum := sha256.Sum256([]byte(accountPolicy))
	return &artifacts.PolicyGate{PolicyID: r.PolicyID, PolicyName: r.PolicyName, PolicyVersion: r.PolicyVersion, PolicyHash: r.PolicyHash,
		Outcome: "allow", FiredRuleID: "emails", DecisionReasonCode: "RULE_ALLOWED", Source: artifacts.PolicySourceCustomer,
		DocumentHash: hex.EncodeToString(sum[:]), ActivationHash: activation, Inputs: accountInputs()}
}

// accountPolicy is rerunPolicy for the fixture's route, and accountInputs
// the inputs a server seals for it: with no decision kind attested, the verb
// the rules read is the request's route (psl mapping, section 8.5), which the
// verifier compares with the envelope since v0.32.0.
var accountPolicy = strings.Replace(rerunPolicy, `"value":"tool.send_email"`, `"value":"policy-gate-fixture"`, 1)

func accountInputs() *artifacts.PolicyInputs {
	in := rerunInputs()
	in.Verb = "policy-gate-fixture"
	return in
}

// accountBundle seals an allowed run from a key in account-7, with the
// account's decision beside the key's, and every hash the record carries
// recomputed.
func accountBundle(t *testing.T, activation string) *artifacts.AuditBundle {
	t.Helper()
	b, _ := policyGateFixture(t)
	b.Nrep.AccountID = "account-7"
	b.EPA.AccountPolicyGate = accountGate(t, activation)
	reseal(b)
	return b
}

// reseal recomputes every hash the record itself determines, as a forger
// could; on this unanchored fixture nothing outside the record holds it.
func reseal(b *artifacts.AuditBundle) {
	b.EPA.Hash = artifacts.RecomputeEPAHash(b.EPA)
	b.BundleHash = artifacts.RecomputeBundleHash(b)
	if a := b.BundleAnchor; a != nil {
		a.AnchoredDigest = artifacts.ComputeAnchoredRecordDigest(b)
		a.LeafHashHex = artifacts.ComputeBundleLeafHash(b.Envelope.EnvelopeID, a.AnchoredDigest)
	}
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	return path
}

func TestAnAccountRecordVerifiesAndNamesItsAccount(t *testing.T) {
	b := accountBundle(t, strings.Repeat("a", 64))
	r := verify(b)
	if !r.AllPassed || r.AccountID != "account-7" || r.AccountPolicyGate == nil || !r.AccountPolicyGate.Present {
		t.Fatalf("tier=%s account=%q gate=%+v cross=%v", r.VerdictTier, r.AccountID, r.AccountPolicyGate, r.CrossChecks)
	}
	if r.AccountPolicyGate.Source != artifacts.PolicySourceCustomer || policyAuthor(*r.AccountPolicyGate) != "written by the customer; Verdifax did not write, review or approve it" {
		t.Fatalf("the account policy must read as the customer's: %+v", r.AccountPolicyGate)
	}
	printAccount(r.AccountID, r.AccountPolicyGate, nil)
}

// Each sealed account value is covered: changing one after sealing, without
// a forger's recomputation, fails, and each changes the digest the record's
// complete-record anchor logs.
func TestTheAccountFieldsAreCoveredByTheRecordsHashes(t *testing.T) {
	for name, change := range map[string]func(*artifacts.AuditBundle){
		"the account":          func(b *artifacts.AuditBundle) { b.Nrep.AccountID = "account-8" },
		"the account removed":  func(b *artifacts.AuditBundle) { b.Nrep.AccountID = "" },
		"the account's rule":   func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate.FiredRuleID = "default" },
		"the account's inputs": func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate.Inputs.Classification = "PUBLIC" },
		"the account's change": func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate.ActivationHash = strings.Repeat("b", 64) },
		"the decision removed": func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate = nil },
	} {
		t.Run(name, func(t *testing.T) {
			b := accountBundle(t, strings.Repeat("a", 64))
			before := artifacts.ComputeAnchoredRecordDigest(b)
			change(b)
			if verify(b).AllPassed {
				t.Fatal("an edited account value passed")
			}
			b.EPA.Hash = artifacts.RecomputeEPAHash(b.EPA)
			b.BundleHash = artifacts.RecomputeBundleHash(b)
			if artifacts.ComputeAnchoredRecordDigest(b) == before {
				t.Fatal("the anchored record digest does not cover this value")
			}
		})
	}
}

// What only an account policy can be. A forger who recomputes every hash
// still fails each of these.
func TestAnAccountDecisionMustBeAnAccountPolicys(t *testing.T) {
	for name, change := range map[string]func(*artifacts.AuditBundle){
		"no account named":                  func(b *artifacts.AuditBundle) { b.Nrep.AccountID = "" },
		"an account Verdifax never assigns": func(b *artifacts.AuditBundle) { b.Nrep.AccountID = "acme" },
		"a leading zero":                    func(b *artifacts.AuditBundle) { b.Nrep.AccountID = "account-07" },
		"named as Verdifax's":               func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate.Source = artifacts.PolicySourceVerdifax },
		"no author":                         func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate.Source = "" },
		"no change named":                   func(b *artifacts.AuditBundle) { b.EPA.AccountPolicyGate.ActivationHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			b := accountBundle(t, strings.Repeat("a", 64))
			change(b)
			reseal(b)
			if r := verify(b); r.AllPassed || r.VerdictTier != "FAILED" {
				t.Fatalf("passed: tier=%s", r.VerdictTier)
			}
		})
	}
}

// A key with no policy of its own runs under Verdifax's built-in policy,
// which admits every request and keeps the code scan; beside an account
// policy the record names both, and verifies.
func TestTheBuiltInKeyGateBesideAnAccountPolicyVerifies(t *testing.T) {
	b := accountBundle(t, strings.Repeat("a", 64))
	b.EPA.PolicyGate.Source = ""
	reseal(b)
	if r := verify(b); !r.AllPassed || r.AccountPolicyGate == nil || policyFailed(*r.AccountPolicyGate) {
		t.Fatalf("tier=%s %+v", r.VerdictTier, r.AccountPolicyGate)
	}
}

// A record with no account hashes and verifies as before, and an account
// number alone, with no account policy, verifies.
func TestARecordWithoutAnAccountPolicyStillVerifies(t *testing.T) {
	b, _ := policyGateFixture(t)
	before := b.BundleHash
	reseal(b)
	if b.BundleHash != before {
		t.Fatal("a record with no account no longer hashes as before")
	}
	b.Nrep.AccountID = "account-12"
	reseal(b)
	if r := verify(b); !r.AllPassed || r.AccountID != "account-12" || r.AccountPolicyGate != nil {
		t.Fatalf("tier=%s %+v", r.VerdictTier, r.AccountPolicyGate)
	}
}

// --account-policy runs the account's rules again. The right document
// passes; a decision the rules do not reach, or another document, fails.
func TestTheAccountPolicyDocumentIsChecked(t *testing.T) {
	doc := writeTemp(t, "account-policy.json", []byte(accountPolicy))
	r := verify(accountBundle(t, strings.Repeat("a", 64)))
	applyAccountFlags(r, doc, "")
	if !r.AllPassed || !r.AccountPolicyGate.DocumentMatch || !r.AccountPolicyGate.RulesChecked {
		t.Fatalf("%+v", r.AccountPolicyGate)
	}

	// The account's rules refuse restricted data; a record claiming they
	// allowed it fails, though every hash agrees.
	b := accountBundle(t, strings.Repeat("a", 64))
	b.EPA.AccountPolicyGate.Inputs.Classification = "RESTRICTED"
	reseal(b)
	refused := verify(b)
	if !refused.AllPassed {
		t.Fatal("without the document the record cannot be judged on its rules")
	}
	applyAccountFlags(refused, doc, "")
	if refused.AllPassed || refused.VerdictTier != "FAILED" {
		t.Fatal("a run the account policy refuses passed as allowed")
	}

	other := writeTemp(t, "other.json", []byte(strings.Replace(accountPolicy, `"policy_version":"3"`, `"policy_version":"4"`, 1)))
	wrong := verify(accountBundle(t, strings.Repeat("a", 64)))
	applyAccountFlags(wrong, other, "")
	if wrong.AllPassed {
		t.Fatal("another document passed")
	}

	plain, _ := policyGateFixture(t)
	none := verify(plain)
	applyAccountFlags(none, doc, "")
	if none.AllPassed || none.AccountPolicyGate == nil || !strings.Contains(none.AccountPolicyGate.Reason, "--account-policy") {
		t.Fatalf("--account-policy on a record with no account decision passed: %+v", none.AccountPolicyGate)
	}
}

// --account-policy-history checks the account's chain, and that it is the
// record's account and holds the record's change.
func TestTheAccountHistoryIsChecked(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	chain := activationChainFor(t, l, 2, "account-7")
	data, encodeErr := json.Marshal(chain)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	path := writeTemp(t, "account-history.json", data)

	r := verify(accountBundle(t, chain[1].ActivationHash))
	applyAccountFlags(r, "", path)
	if !r.AllPassed || !r.AccountPolicyHistory.OK || !r.AccountPolicyHistory.RecordInChain {
		t.Fatalf("%+v", r.AccountPolicyHistory)
	}
	printAccount(r.AccountID, r.AccountPolicyGate, r.AccountPolicyHistory)

	outside := verify(accountBundle(t, strings.Repeat("9", 64)))
	applyAccountFlags(outside, "", path)
	if outside.AllPassed {
		t.Fatal("a change outside the account's history passed")
	}

	b := accountBundle(t, chain[1].ActivationHash)
	b.Nrep.AccountID = "account-8"
	reseal(b)
	another := verify(b)
	applyAccountFlags(another, "", path)
	if another.AllPassed || !strings.Contains(another.AccountPolicyHistory.Reason, "account-8") {
		t.Fatalf("another account's history passed: %+v", another.AccountPolicyHistory)
	}

	keyChain, keyEncodeErr := json.Marshal(activationChain(t, l, 2))
	if keyEncodeErr != nil {
		t.Fatal(keyEncodeErr)
	}
	keyPath := writeTemp(t, "key-history.json", keyChain)
	keyHistory := verify(accountBundle(t, chain[1].ActivationHash))
	applyAccountFlags(keyHistory, "", keyPath)
	if keyHistory.AllPassed {
		t.Fatal("a key's history passed as the account's")
	}

	plain, _ := policyGateFixture(t)
	noAccount := verify(plain)
	applyAccountFlags(noAccount, "", path)
	if noAccount.AllPassed {
		t.Fatal("an account history passed on a record with no account")
	}

	if code := runAccountHistoryMode(path, true); code != 0 {
		t.Fatalf("an account's own history gave exit %d", code)
	}
	if code := runAccountHistoryMode(keyPath, true); code != 1 {
		t.Fatalf("a key's history read alone as an account's gave exit %d", code)
	}
	if code := runAccountHistoryMode(path+"x", true); code != 2 {
		t.Fatalf("a missing file gave exit %d", code)
	}
}

// Every change in an account's history must be the same account's.
func TestAnAccountHistoryHoldsOneAccount(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	first := activationChainFor(t, l, 1, "account-7")
	second := activationChainFor(t, l, 2, "account-8")
	second[0] = first[0]
	second[1].PreviousActivationHash = first[0].ActivationHash
	sealActivation(t, l, &second[1], 0)
	if got := checkAccountChain(historyOf(t, second)); got.OK {
		t.Fatalf("a history crossing accounts passed: %+v", got)
	}
}

// A receipt of a run the gate admitted and a later check stopped must not
// seal a refusal from either policy; a refused run's receipt may.
func TestAHaltedRunWasAllowedByBothPolicies(t *testing.T) {
	deny := PolicyGateCheck{Present: true, Outcome: "deny"}
	allow := PolicyGateCheck{Present: true, Outcome: "allow"}
	undecided := PolicyGateCheck{Present: true}
	for kind := range haltedReceiptKinds {
		if admittedDecisionError(kind, "account policy", deny) == nil {
			t.Errorf("a %s sealing a refusal passed", kind)
		}
		if admittedDecisionError(kind, "account policy", allow) != nil || admittedDecisionError(kind, "account policy", undecided) != nil {
			t.Errorf("a %s sealing an allow or no decision failed", kind)
		}
	}
	if admittedDecisionError("deny_receipt", "account policy", deny) != nil {
		t.Error("a refused run's refusal failed")
	}
}

// A refused run's receipt carries the account decision the same way.
func TestAReceiptsAccountDecisionIsRead(t *testing.T) {
	sealed := sealedCheck(t)
	binding := &artifacts.PolicyBinding{Source: sealed.Source, PolicyHash: sealed.PolicyHash, DocumentHash: sealed.DocumentHash,
		ActivationHash: strings.Repeat("a", 64), Outcome: "deny", FiredRuleID: "no-restricted", Inputs: rerunInputs()}
	binding.Inputs.Classification = "RESTRICTED"
	ctx := &artifacts.ReceiptContext{AccountID: "account-7", AccountPolicy: binding}
	got := accountGateOfReceipt(ctx, "")
	if got == nil || policyFailed(*got) || got.Outcome != "deny" {
		t.Fatalf("%+v", got)
	}
	checked := checkPolicyDocument(*got, []byte(rerunPolicy))
	if !checked.DocumentMatch || !checked.RulesChecked {
		t.Fatalf("the account's rules must reach the sealed refusal: %+v", checked)
	}
	ctx.AccountID = ""
	if got := accountGateOfReceipt(ctx, ""); !policyFailed(*got) {
		t.Fatal("a receipt's account decision with no account passed")
	}
	if accountGateOfReceipt(&artifacts.ReceiptContext{}, "") != nil {
		t.Fatal("a receipt with no account decision reported one")
	}
}

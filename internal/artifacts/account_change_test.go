package artifacts

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// testOwnerKey signs the test records the owner decides.
var testOwnerKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))

func ownerSign(change, subject string) *OwnerSignature {
	o := &OwnerSignature{PublicKey: base64.StdEncoding.EncodeToString(testOwnerKey.Public().(ed25519.PublicKey)),
		SignedAt: "2026-11-12T18:00:00Z", Nonce: strings.Repeat("0a", 16)}
	o.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(testOwnerKey, OwnerChangePreimage("account-7", change, subject, o.SignedAt, o.Nonce)))
	return o
}

func testLink() SignalLink {
	return SignalLink{Account: "account-7", Sequence: 4, PreviousSignalHash: strings.Repeat("b", 64)}
}

func sealedAccountChange(action, decidedBy string, keyID int64, value string) *AccountChange {
	c := &AccountChange{Format: AccountChangeFormat, Action: action, DecidedBy: decidedBy, KeyID: keyID, Value: value,
		ChangedAt: "2026-11-12T18:00:00Z", Signal: testLink()}
	if decidedBy == DecidedByOwner {
		c.OwnerSignature = ownerSign(action, value)
	}
	c.AccountChangeHash = c.ComputeHash()
	return c
}

// Round 60: each account-change action has one decider. The owner sets its
// own account's settings; only Verdifax makes the changes an admin key makes,
// so a record that names the wrong decider fails, and every action is one the
// rules know.
func TestAccountChangeDeciders(t *testing.T) {
	if len(AccountChangeActions) != len(accountChangeRules) {
		t.Fatalf("every action is listed once: %d listed, %d with rules", len(AccountChangeActions), len(accountChangeRules))
	}
	good := []*AccountChange{
		sealedAccountChange(AccountCreated, DecidedByVerdifax, 0, "trial"),
		sealedAccountChange(AccountRequestKeyCleared, DecidedByVerdifax, 12, ""),
		sealedAccountChange(AccountKeyTierSet, DecidedByVerdifax, 12, "production"),
		sealedAccountChange(AccountKeySubmitterClassSet, DecidedByVerdifax, 12, "third-party"),
		sealedAccountChange(AccountKeyBillingSet, DecidedByVerdifax, 12, "linked"),
		sealedAccountChange(AccountOwnerKeyReplacement, DecidedByVerdifax, 0, "2026-11-15T18:00:00Z"),
		sealedAccountChange(AccountSettingOwnerReplace, DecidedByOwner, 0, SettingBlocked),
		sealedAccountChange(AccountSettingVerdifaxDelete, DecidedByOwner, 0, SettingAllowed),
	}
	seen := map[string]bool{}
	for _, c := range good {
		seen[c.Action] = true
		if err := c.Validate(); err != nil {
			t.Errorf("%s by %s must be valid: %v", c.Action, c.DecidedBy, err)
		}
	}
	for _, a := range AccountChangeActions {
		if !seen[a] {
			t.Errorf("action %s has no valid example here", a)
		}
	}
	bad := map[string]*AccountChange{
		"the owner setting a tier":           sealedAccountChange(AccountKeyTierSet, DecidedByOwner, 12, "production"),
		"Verdifax setting the owner's block": sealedAccountChange(AccountSettingOwnerReplace, DecidedByVerdifax, 0, SettingAllowed),
		"a key action naming no key":         sealedAccountChange(AccountKeyTierSet, DecidedByVerdifax, 0, "trial"),
		"a setting naming a key":             sealedAccountChange(AccountSettingVerdifaxDelete, DecidedByOwner, 3, SettingBlocked),
		"a value outside the action's set":   sealedAccountChange(AccountSettingOwnerReplace, DecidedByOwner, 0, "maybe"),
		"an empty free value":                sealedAccountChange(AccountOwnerKeyReplacement, DecidedByVerdifax, 0, ""),
		"an unknown action":                  sealedAccountChange("account.renamed", DecidedByVerdifax, 0, "x"),
		"an unknown decider":                 sealedAccountChange(AccountCreated, "someone", 0, "trial"),
	}
	for name, c := range bad {
		if c.Validate() == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// The hash covers every field but itself and the anchor, so a change to any
// sealed value changes it. The fixed value pins the recipe: the verifier and
// the server compute it from this same file.
func TestAccountChangeAndDeletionHashes(t *testing.T) {
	c := sealedAccountChange(AccountKeyTierSet, DecidedByVerdifax, 12, "production")
	d := &RunDeletion{Format: RunDeletionFormat, DecidedBy: DecidedByOwner, RunID: 3468, RecordHash: strings.Repeat("c", 64),
		JobID: "job-1", StepID: "verdict", ChangedAt: "2026-11-12T18:00:00Z", Signal: testLink()}
	d.OwnerSignature = ownerSign(SignalRunDeleted, d.DeletionSubject())
	d.DeletionHash = d.ComputeHash()
	if err := d.Validate(); err != nil {
		t.Fatalf("a deletion must be valid: %v", err)
	}
	for name, mutate := range map[string]func(){
		"value": func() { c.Value = "trial" }, "key": func() { c.KeyID = 13 }, "decider": func() { c.DecidedBy = DecidedByOwner },
		"time": func() { c.ChangedAt = "2026-11-12T18:00:01Z" }, "place": func() { c.Signal.Sequence = 5 },
	} {
		before := c.ComputeHash()
		mutate()
		if c.ComputeHash() == before {
			t.Errorf("an account change's hash must cover its %s", name)
		}
	}
	if c.OwnerSignature != nil {
		t.Fatal("a Verdifax change carries no owner signature")
	}
	withEntries := *d
	withEntries.LogEntries = []string{"3541949910", "3548235039"}
	withEntries.DeletionHash = withEntries.ComputeHash()
	if withEntries.Validate() != nil || withEntries.DeletionHash == d.DeletionHash {
		t.Fatal("a deletion seals the deleted record's log entries")
	}
	for name, bad := range map[string][]string{"out of order": {"3548235039", "3541949910"}, "repeated": {"35", "35"},
		"not a number": {"35a"}, "a leading zero": {"035"}, "empty": {""}} {
		x := withEntries
		x.LogEntries = bad
		x.DeletionHash = x.ComputeHash()
		if x.Validate() == nil {
			t.Errorf("log entries %s must be refused", name)
		}
	}
	for name, mutate := range map[string]func(){
		"run": func() { d.RunID = 3469 }, "record": func() { d.RecordHash = strings.Repeat("d", 64) },
		"decider": func() { d.DecidedBy = DecidedByVerdifax }, "step": func() { d.StepID = "intake" },
	} {
		before := d.ComputeHash()
		mutate()
		if d.ComputeHash() == before {
			t.Errorf("a run deletion's hash must cover its %s", name)
		}
	}
	if c.LeafHash() == d.LeafHash() {
		t.Fatal("the two records' leaves must differ by kind")
	}
}

// Key change v2 seals who decided; a v1 record keeps its recipe and reads as
// the owner's. Only Verdifax creates or revokes an owner key.
func TestKeyChangeV2(t *testing.T) {
	v1 := &KeyChange{Format: KeyChangeFormatV1, Action: SignalKeyCreated, KeyID: 9, KeyScope: KeyScopeRun, Name: "member",
		ChangedAt: "2026-11-10T00:00:00Z", Signal: testLink()}
	v1.KeyChangeHash = v1.ComputeHash()
	link := testLink()
	want := lengthPrefixedHash(append([]string{KeyChangeFormatV1, SignalKeyCreated, "9", KeyScopeRun, "", "member", "2026-11-10T00:00:00Z"}, link.fields()...))
	if v1.KeyChangeHash != want || v1.Validate() != nil || v1.Decider() != DecidedByOwner {
		t.Fatalf("a v1 key change keeps its recipe and reads as the owner's: %v", v1.Validate())
	}
	v1.DecidedBy = DecidedByVerdifax
	if v1.Validate() == nil {
		t.Fatal("a v1 key change seals no decided_by")
	}
	v2 := &KeyChange{Format: KeyChangeFormat, Action: SignalKeyRevoked, DecidedBy: DecidedByVerdifax, KeyID: 9, KeyScope: KeyScopeRun,
		Name: "member", ChangedAt: "2026-11-12T00:00:00Z", Signal: testLink()}
	v2.KeyChangeHash = v2.ComputeHash()
	if v2.Validate() != nil || v2.Decider() != DecidedByVerdifax {
		t.Fatalf("a Verdifax revocation must be valid: %v", v2.Validate())
	}
	byOwner := *v2
	byOwner.DecidedBy = DecidedByOwner
	if byOwner.ComputeHash() == v2.KeyChangeHash {
		t.Fatal("v2's hash must cover decided_by")
	}
	owner := *v2
	owner.KeyScope = KeyScopeOwner
	owner.KeyChangeHash = owner.ComputeHash()
	if owner.Validate() != nil {
		t.Fatalf("Verdifax revoking an owner key must be valid: %v", owner.Validate())
	}
	owner.DecidedBy = DecidedByOwner
	owner.KeyChangeHash = owner.ComputeHash()
	if owner.Validate() == nil {
		t.Fatal("an owner key change decided by the owner must be refused")
	}
	if PublicationByVerdifax != DecidedByVerdifax || PublicationByOwner != DecidedByOwner {
		t.Fatal("a publication and a key change name their deciders alike")
	}
}

// Round 60: a change the owner decides is signed by the owner's request key,
// which Verdifax never holds, and the record seals the signature. A missing,
// forged or misplaced signature fails, so the server cannot make an owner's
// setting or deletion of its own.
func TestOwnerChangesAreSignedByTheOwner(t *testing.T) {
	c := sealedAccountChange(AccountSettingVerdifaxDelete, DecidedByOwner, 0, SettingAllowed)
	if err := c.Validate(); err != nil {
		t.Fatalf("a signed owner setting must be valid: %v", err)
	}
	flipped := *c
	flipped.Value = SettingBlocked
	flipped.AccountChangeHash = flipped.ComputeHash()
	if flipped.Validate() == nil {
		t.Fatal("a signature over allowed must not cover blocked")
	}
	other := *c
	other.Signal.Account = "account-8"
	other.AccountChangeHash = other.ComputeHash()
	if other.Validate() == nil {
		t.Fatal("a signature for one account must not cover another")
	}
	unsigned := *c
	unsigned.OwnerSignature = nil
	unsigned.AccountChangeHash = unsigned.ComputeHash()
	if unsigned.Validate() == nil {
		t.Fatal("an owner setting without the owner's signature must fail")
	}
	verdifax := sealedAccountChange(AccountKeyTierSet, DecidedByVerdifax, 12, "trial")
	verdifax.OwnerSignature = ownerSign(AccountKeyTierSet, "trial")
	verdifax.AccountChangeHash = verdifax.ComputeHash()
	if verdifax.Validate() == nil {
		t.Fatal("a Verdifax change must not carry an owner signature")
	}
	if base := c.ComputeHash(); func() string { x := *c; x.OwnerSignature = ownerSign(c.Action, "x"); return x.ComputeHash() }() == base {
		t.Fatal("the hash must cover the owner's signature")
	}
	d := &RunDeletion{Format: RunDeletionFormat, DecidedBy: DecidedByOwner, RunID: 3468, RecordHash: strings.Repeat("c", 64),
		ChangedAt: "2026-11-12T18:00:00Z", Signal: testLink()}
	d.OwnerSignature = ownerSign(SignalRunDeleted, "3469:"+d.RecordHash)
	d.DeletionHash = d.ComputeHash()
	if d.Validate() == nil {
		t.Fatal("a signature over another run must not cover this deletion")
	}
}

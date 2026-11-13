package artifacts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
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
		requestKeyChange(AccountRequestKeyRegistered, DecidedByOwner, publicOf(testHolderKey), nil),
		requestKeyChange(AccountRequestKeyRotated, DecidedByOwner, publicOf(testNextKey), approve(testHolderKey, publicOf(testNextKey))),
		requestKeyChange(AccountRequestKeyCleared, DecidedByOwner, "", approve(testHolderKey, "")),
		sealedAccountChange(AccountWebhookSubscribed, DecidedByOwner, 0, WebhookValue("https://hooks.example.com/in", nil)),
		sealedAccountChange(AccountWebhookDeleted, DecidedByOwner, 0, WebhookValue("https://hooks.example.com/in", []string{"run.refused", "account.changed"})),
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
		"the owner setting a tier":             sealedAccountChange(AccountKeyTierSet, DecidedByOwner, 12, "production"),
		"Verdifax setting the owner's block":   sealedAccountChange(AccountSettingOwnerReplace, DecidedByVerdifax, 0, SettingAllowed),
		"Verdifax adding a webhook":            sealedAccountChange(AccountWebhookSubscribed, DecidedByVerdifax, 0, WebhookValue("https://x.example/", nil)),
		"a webhook change naming the address":  sealedAccountChange(AccountWebhookSubscribed, DecidedByOwner, 0, "https://hooks.example.com/in"),
		"a webhook change naming a key":        sealedAccountChange(AccountWebhookDeleted, DecidedByOwner, 12, WebhookValue("https://x.example/", nil)),
		"a webhook change with unsorted kinds": sealedAccountChange(AccountWebhookSubscribed, DecidedByOwner, 0, "sha256="+strings.Repeat("a", 64)+" kinds=run.refused,account.changed,"),
		"a key action naming no key":           sealedAccountChange(AccountKeyTierSet, DecidedByVerdifax, 0, "trial"),
		"a setting naming a key":               sealedAccountChange(AccountSettingVerdifaxDelete, DecidedByOwner, 3, SettingBlocked),
		"a value outside the action's set":     sealedAccountChange(AccountSettingOwnerReplace, DecidedByOwner, 0, "maybe"),
		"an empty free value":                  sealedAccountChange(AccountOwnerKeyReplacement, DecidedByVerdifax, 0, ""),
		"an unknown action":                    sealedAccountChange("account.renamed", DecidedByVerdifax, 0, "x"),
		"an unknown decider":                   sealedAccountChange(AccountCreated, "someone", 0, "trial"),
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

// testHolderKey and testNextKey are a key's request keys, before and after a
// rotation.
var (
	testHolderKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
	testNextKey   = ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32)))
)

func publicOf(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func approve(by ed25519.PrivateKey, newKey string) *RequestKeyApproval {
	a := &RequestKeyApproval{PublicKey: publicOf(by), SignedAt: "2026-11-12T18:00:00Z", Nonce: strings.Repeat("0b", 16)}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(by, RequestKeyChangePreimage(newKey, a.SignedAt, a.Nonce)))
	return a
}

func requestKeyChange(action, decidedBy, value string, approval *RequestKeyApproval) *AccountChange {
	c := &AccountChange{Format: AccountChangeFormat, Action: action, DecidedBy: decidedBy, KeyID: 12, Value: value,
		ChangedAt: "2026-11-12T18:00:00Z", RequestKeyApproval: approval, Signal: testLink()}
	c.AccountChangeHash = c.ComputeHash()
	return c
}

// Round 61, N22: a key's request key is registered, rotated with the current
// key's approval, or cleared by its holder with that approval, each sealed as
// the account's own change; only Verdifax's clear carries no approval. A
// rotation the current key did not approve, an approval over another key, an
// approval on a registration and an owner-key signature on a holder's change
// all fail, and the approval joins the hash with its own label.
func TestRequestKeyChangesCarryTheirChain(t *testing.T) {
	next := publicOf(testNextKey)
	good := map[string]*AccountChange{
		"a registration":           requestKeyChange(AccountRequestKeyRegistered, DecidedByOwner, publicOf(testHolderKey), nil),
		"an approved rotation":     requestKeyChange(AccountRequestKeyRotated, DecidedByOwner, next, approve(testHolderKey, next)),
		"the holder's clear":       requestKeyChange(AccountRequestKeyCleared, DecidedByOwner, "", approve(testHolderKey, "")),
		"Verdifax's clear":         requestKeyChange(AccountRequestKeyCleared, DecidedByVerdifax, "", nil),
		"a rotation to a same key": requestKeyChange(AccountRequestKeyRotated, DecidedByOwner, publicOf(testHolderKey), approve(testHolderKey, publicOf(testHolderKey))),
	}
	for name, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("%s must be valid: %v", name, err)
		}
		if !IsRequestKeyAction(c.Action) {
			t.Errorf("%s is a request-key action", name)
		}
	}
	withOwnerSig := requestKeyChange(AccountRequestKeyRegistered, DecidedByOwner, next, nil)
	withOwnerSig.OwnerSignature = ownerSign(AccountRequestKeyRegistered, next)
	withOwnerSig.AccountChangeHash = withOwnerSig.ComputeHash()
	bad := map[string]*AccountChange{
		"a rotation with no approval":                 requestKeyChange(AccountRequestKeyRotated, DecidedByOwner, next, nil),
		"an approval over another key":                requestKeyChange(AccountRequestKeyRotated, DecidedByOwner, next, approve(testHolderKey, publicOf(testOwnerKey))),
		"a holder's clear with no approval":           requestKeyChange(AccountRequestKeyCleared, DecidedByOwner, "", nil),
		"a registration with an approval":             requestKeyChange(AccountRequestKeyRegistered, DecidedByOwner, next, approve(testHolderKey, next)),
		"Verdifax's clear with an approval":           requestKeyChange(AccountRequestKeyCleared, DecidedByVerdifax, "", approve(testHolderKey, "")),
		"Verdifax registering a request key":          requestKeyChange(AccountRequestKeyRegistered, DecidedByVerdifax, next, nil),
		"a registration of no key":                    requestKeyChange(AccountRequestKeyRegistered, DecidedByOwner, "not-a-key", nil),
		"an owner-key signature on a holder's change": withOwnerSig,
		"an approval on an owner setting": func() *AccountChange {
			c := sealedAccountChange(AccountSettingOwnerReplace, DecidedByOwner, 0, SettingBlocked)
			c.RequestKeyApproval = approve(testHolderKey, SettingBlocked)
			c.AccountChangeHash = c.ComputeHash()
			return c
		}(),
	}
	for name, c := range bad {
		if c.Validate() == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	rotated := good["an approved rotation"]
	before := rotated.ComputeHash()
	x := *rotated
	x.RequestKeyApproval = approve(testOwnerKey, next)
	if x.ComputeHash() == before {
		t.Fatal("the hash must cover the approval")
	}
	// An approval and an owner signature with the same four values never
	// hash alike: the approval's fields carry their own label.
	sig := &OwnerSignature{PublicKey: "p", Signature: "s", SignedAt: "t", Nonce: "n"}
	asApproval := &AccountChange{Format: AccountChangeFormat, RequestKeyApproval: &RequestKeyApproval{"p", "s", "t", "n"}}
	asSignature := &AccountChange{Format: AccountChangeFormat, OwnerSignature: sig}
	if asApproval.ComputeHash() == asSignature.ComputeHash() {
		t.Fatal("an approval must not hash as an owner signature")
	}
	// A record with no approval hashes as one sealed before round 61.
	plain := sealedAccountChange(AccountKeyTierSet, DecidedByVerdifax, 12, "production")
	link := testLink()
	want := lengthPrefixedHash(append([]string{AccountChangeFormat, AccountKeyTierSet, DecidedByVerdifax, "12", "production", "2026-11-12T18:00:00Z"}, link.fields()...))
	if plain.AccountChangeHash != want {
		t.Fatal("a record with no approval must keep the round 60 recipe")
	}
}

// Round 61: a job step's tombstone seals the deleted record's own job links,
// behind their own label, so a job stays checkable through it; a tombstone
// sealed before carries none and hashes exactly as before, and a changed
// link breaks the hash.
func TestARunDeletionSealsItsJobLinks(t *testing.T) {
	old := &RunDeletion{Format: RunDeletionFormat, DecidedBy: DecidedByVerdifax, RunID: 3468, RecordHash: strings.Repeat("c", 64),
		JobID: "job-1", StepID: "credit", LogEntries: []string{"3541949910"}, ChangedAt: "2026-11-12T18:00:00Z", Signal: testLink()}
	old.DeletionHash = old.ComputeHash()
	link := testLink()
	want := lengthPrefixedHash(append([]string{RunDeletionFormat, DecidedByVerdifax, "3468", strings.Repeat("c", 64), "job-1", "credit", "1",
		"3541949910", "2026-11-12T18:00:00Z"}, link.fields()...))
	if old.DeletionHash != want || old.Validate() != nil {
		t.Fatalf("a tombstone with no job links keeps the round 60 recipe: %v", old.Validate())
	}
	linked := *old
	linked.JobLinks = &DeletedJobLinks{PreviousRecordHashes: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, Final: true}
	linked.DeletionHash = linked.ComputeHash()
	if linked.Validate() != nil || linked.DeletionHash == old.DeletionHash {
		t.Fatalf("a tombstone seals its job links: %v", linked.Validate())
	}
	// The links join behind their own label, each list with its length,
	// after the owner's signature and before the place in the feed.
	wantLinked := lengthPrefixedHash(append([]string{RunDeletionFormat, DecidedByVerdifax, "3468", strings.Repeat("c", 64), "job-1", "credit", "1",
		"3541949910", "2026-11-12T18:00:00Z", "job_links", "2", strings.Repeat("a", 64), strings.Repeat("b", 64), "0", "true"}, link.fields()...))
	if linked.DeletionHash != wantLinked {
		t.Fatal("the job links' recipe changed")
	}
	empty := *old
	empty.JobLinks = &DeletedJobLinks{}
	if empty.ComputeHash() == old.DeletionHash {
		t.Fatal("a first step's empty links must hash apart from no links at all")
	}
	for name, mutate := range map[string]func(l *DeletedJobLinks){
		"a previous hash":  func(l *DeletedJobLinks) { l.PreviousRecordHashes[0] = strings.Repeat("d", 64) },
		"the final flag":   func(l *DeletedJobLinks) { l.Final = false },
		"an external link": func(l *DeletedJobLinks) { l.ExternalPrevious = []string{strings.Repeat("e", 64)} },
		"a link moved over": func(l *DeletedJobLinks) {
			l.ExternalPrevious, l.PreviousRecordHashes = l.PreviousRecordHashes[1:], l.PreviousRecordHashes[:1]
		},
	} {
		x := linked
		l := *linked.JobLinks
		l.PreviousRecordHashes = append([]string(nil), l.PreviousRecordHashes...)
		mutate(&l)
		x.JobLinks = &l
		if x.ComputeHash() == linked.DeletionHash {
			t.Errorf("the hash must cover %s", name)
		}
	}
	for name, bad := range map[string]*RunDeletion{
		"links on a record in no job": {Format: RunDeletionFormat, DecidedBy: DecidedByVerdifax, RunID: 1, RecordHash: strings.Repeat("c", 64),
			ChangedAt: "2026-11-12T18:00:00Z", Signal: testLink(), JobLinks: &DeletedJobLinks{}},
		"unsorted links": func() *RunDeletion {
			x := *old
			x.JobLinks = &DeletedJobLinks{PreviousRecordHashes: []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}}
			return &x
		}(),
	} {
		bad.DeletionHash = bad.ComputeHash()
		if bad.Validate() == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// Round 62 (R266): a webhook change seals the address's SHA-256 and the kinds
// sorted, the value every SDK signs, fixed by the shared vector.
func TestWebhookValueMatchesTheSharedVector(t *testing.T) {
	text, readErr := os.ReadFile("testdata/sdk-webhook-change-vector.json")
	if readErr != nil {
		t.Fatalf("read the vector: %v", readErr)
	}
	var vector struct {
		Changes struct {
			Subscribe string `json:"subscribe"`
			Delete    string `json:"delete"`
		} `json:"changes"`
		Cases []struct {
			Name  string   `json:"name"`
			URL   string   `json:"url"`
			Types []string `json:"types"`
			Value string   `json:"value"`
		} `json:"cases"`
	}
	if decodeErr := json.Unmarshal(text, &vector); decodeErr != nil {
		t.Fatalf("decode the vector: %v", decodeErr)
	}
	if vector.Changes.Subscribe != AccountWebhookSubscribed || vector.Changes.Delete != AccountWebhookDeleted || len(vector.Cases) == 0 {
		t.Fatalf("the vector names the changes %+v", vector.Changes)
	}
	for _, c := range vector.Cases {
		if got := WebhookValue(c.URL, c.Types); got != c.Value {
			t.Errorf("%s: %q, want %q", c.Name, got, c.Value)
		}
	}
}

// Round 62: a webhook change seals the address's SHA-256 and the kinds sorted,
// so the same subscription gives the same value in every SDK.
func TestWebhookValue(t *testing.T) {
	sum := sha256.Sum256([]byte("https://hooks.example.com/in"))
	want := "sha256=" + hex.EncodeToString(sum[:]) + " kinds=account.changed,run.refused"
	if got := WebhookValue("https://hooks.example.com/in", []string{"run.refused", "account.changed"}); got != want {
		t.Fatalf("WebhookValue = %q, want %q", got, want)
	}
	if got := WebhookValue("https://hooks.example.com/in", nil); got != "sha256="+hex.EncodeToString(sum[:])+" kinds=all" {
		t.Fatalf("every kind: %q", got)
	}
}

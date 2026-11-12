package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 60: a feed holds a key change in either format, an account change and
// a run deletion, each with who decided, and the report names them.
func TestAccountChangesAndDeletionsVerify(t *testing.T) {
	f := newFeedBuilder(t)
	f.byVerdifax = true
	f.accountChange(artifacts.AccountCreated, 0, "trial")
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner)
	f.byVerdifax = false
	f.v1KeyChanges = true
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeRun)
	f.v1KeyChanges = false
	f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
	f.runDeletion(901)
	f.byVerdifax = true
	f.accountChange(artifacts.AccountKeyTierSet, 43, "production")
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || len(c.Entries) != 6 {
		t.Fatalf("a feed of account changes and a deletion must verify: %+v", c)
	}
	want := []struct{ kind, decider, change, scope string }{
		{artifacts.SignalAccountChanged, "verdifax_admin", artifacts.AccountCreated, ""},
		{artifacts.SignalKeyCreated, "verdifax_admin", "", artifacts.KeyScopeOwner},
		{artifacts.SignalKeyCreated, "owner", "", artifacts.KeyScopeRun},
		{artifacts.SignalAccountChanged, "owner", artifacts.AccountSettingVerdifaxDelete, ""},
		{artifacts.SignalRunDeleted, "owner", "", ""},
		{artifacts.SignalAccountChanged, "verdifax_admin", artifacts.AccountKeyTierSet, ""},
	}
	for i, w := range want {
		e := c.Entries[i]
		if e.Kind != w.kind || e.DecidedBy != w.decider || e.Change != w.change || e.KeyScope != w.scope {
			t.Errorf("event %d reads %+v, want %+v", i+1, e, w)
		}
	}
	if c.Entries[3].OwnerSignedBy == "" || c.Entries[4].OwnerSignedBy != c.Entries[3].OwnerSignedBy || c.Entries[5].OwnerSignedBy != "" {
		t.Fatalf("an owner change names the key that signed it, and a Verdifax change names none: %+v", c.Entries)
	}
	if c.Entries[4].RunID != 901 || c.Entries[5].Value != "production" {
		t.Fatalf("the deletion names its run and the change its value: %+v", c.Entries)
	}
}

// The owner's blocks hold in the feed itself: once the owner blocks Verdifax
// deletion or owner-key replacement, a Verdifax deletion, owner-key change or
// replacement request fails the feed, until the owner allows it again. The
// owner's own deletion is never blocked.
func TestTheOwnersBlocksHoldInTheFeed(t *testing.T) {
	cases := []struct {
		name  string
		build func(f *feedBuilder)
		fails string
	}{
		{"a Verdifax deletion after a deletion block", func(f *feedBuilder) {
			f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
			f.byVerdifax = true
			f.runDeletion(902)
		}, "deleted a record after the owner blocked"},
		{"a Verdifax owner-key revocation after a replacement block", func(f *feedBuilder) {
			f.accountChange(artifacts.AccountSettingOwnerReplace, 0, artifacts.SettingBlocked)
			f.byVerdifax = true
			f.keyChange(artifacts.SignalKeyRevoked, artifacts.KeyScopeOwner)
		}, "changed the account's owner key"},
		{"a replacement request after a replacement block", func(f *feedBuilder) {
			f.accountChange(artifacts.AccountSettingOwnerReplace, 0, artifacts.SettingBlocked)
			f.byVerdifax = true
			f.accountChange(artifacts.AccountOwnerKeyReplacement, 0, "2026-11-15T18:00:00Z")
		}, "changed the account's owner key"},
		{"a Verdifax deletion once the owner allows it again", func(f *feedBuilder) {
			f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
			f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingAllowed)
			f.byVerdifax = true
			f.runDeletion(903)
		}, ""},
		{"the owner's own deletion under its block", func(f *feedBuilder) {
			f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
			f.runDeletion(904)
		}, ""},
		{"a Verdifax member-key revocation under a replacement block", func(f *feedBuilder) {
			f.accountChange(artifacts.AccountSettingOwnerReplace, 0, artifacts.SettingBlocked)
			f.byVerdifax = true
			f.keyChange(artifacts.SignalKeyRevoked, artifacts.KeyScopeRun)
		}, ""},
	}
	for _, tc := range cases {
		f := newFeedBuilder(t)
		tc.build(f)
		c := checkSignalFeed(feedBody(t, f.events), nil)
		switch {
		case tc.fails == "" && !c.OK:
			t.Errorf("%s must verify: %s", tc.name, c.Reason)
		case tc.fails != "" && (c.OK || !strings.Contains(c.Reason, tc.fails)):
			t.Errorf("%s must fail with %q: %+v", tc.name, tc.fails, c)
		}
	}
}

// Every record must carry exactly what its kind and decider allow: an owner
// key changed by the owner, an account change Verdifax may not make, and a
// tampered tombstone each fail.
func TestAccountRecordsAreCheckedWhole(t *testing.T) {
	f := newFeedBuilder(t)
	f.runDeletion(905)
	events := f.events
	tampered := strings.Replace(string(feedBody(t, events)), `"run_id":905,"record_hash":"eeee`, `"run_id":905,"record_hash":"ffff`, 1)
	if c := checkSignalFeed([]byte(tampered), nil); c.OK {
		t.Fatal("a tombstone whose record hash was changed must fail")
	}
	g := newFeedBuilder(t)
	g.keyChange(artifacts.SignalKeyRevoked, artifacts.KeyScopeOwner)
	if c := checkSignalFeed(feedBody(t, g.events), nil); c.OK || !strings.Contains(c.Reason, "only Verdifax creates or revokes an owner key") {
		t.Fatalf("an owner key revoked by the owner must fail: %+v", c)
	}
	h := newFeedBuilder(t)
	h.byVerdifax = true
	h.accountChange(artifacts.AccountSettingOwnerReplace, 0, artifacts.SettingAllowed)
	if c := checkSignalFeed(feedBody(t, h.events), nil); c.OK || !strings.Contains(c.Reason, "only the account's owner makes this change") {
		t.Fatalf("Verdifax setting the owner's block must fail: %+v", c)
	}
}

// Round 60: a deleted stopped run's event is served with its tombstone in
// place of the receipt. The feed still verifies, because the event's hash is
// the receipt's hash the tombstone seals; a tombstone for another run, another
// hash, an entry served beside it, or a tombstone on another kind of event
// fails.
func TestADeletedRecordsEventVerifiesThroughItsTombstone(t *testing.T) {
	build := func(mutate func(e *signalEvent, d *artifacts.RunDeletion)) SignalFeedCheck {
		f := newFeedBuilder(t)
		f.failedRun()
		var receiptHash string
		var doc artifacts.ReceiptDocument
		if err := json.Unmarshal(f.events[0].Data.Entry, &doc); err != nil {
			t.Fatal(err)
		}
		receiptHash = doc.FailureReceipt.Hash
		d := f.runDeletionOf(f.runID, receiptHash)
		e := &f.events[0].Data
		e.Entry, e.Deleted = json.RawMessage("null"), d
		if mutate != nil {
			mutate(e, d)
		}
		return checkSignalFeed(feedBody(t, f.events), nil)
	}
	c := build(nil)
	if !c.OK || c.Entries[0].RecordDeletedBy != "owner" || c.Entries[0].LogEntry != "123456789001" {
		t.Fatalf("a deleted record's event must verify through its tombstone: %+v", c)
	}
	for name, mutate := range map[string]func(e *signalEvent, d *artifacts.RunDeletion){
		"a tombstone for another run": func(e *signalEvent, d *artifacts.RunDeletion) {
			x := *d
			x.RunID++
			x.DeletionHash = x.ComputeHash()
			e.Deleted = &x
		},
		"an entry beside the tombstone": func(e *signalEvent, d *artifacts.RunDeletion) { e.Entry = json.RawMessage(`{"ok":true}`) },
		"a tombstone naming another hash": func(e *signalEvent, d *artifacts.RunDeletion) {
			x := *d
			x.RecordHash = strings.Repeat("9", 64)
			x.DeletionHash = x.ComputeHash()
			e.Deleted = &x
		},
		"a tombstone on a key event": func(e *signalEvent, d *artifacts.RunDeletion) { e.Kind = artifacts.SignalKeyCreated },
	} {
		if c := build(mutate); c.OK {
			t.Errorf("%s must fail", name)
		}
	}
}

// Round 60: a record names the key that signed the owner's change, so the
// check alone proves only that that key signed. --owner-request-key pins the
// owner's own keys: a feed whose owner change another key signed fails, and
// the report lists every key that signed an owner change.
func TestTheOwnersRequestKeyIsPinned(t *testing.T) {
	f := newFeedBuilder(t)
	f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
	body := feedBody(t, f.events)
	own := base64.StdEncoding.EncodeToString(ownerKey.Public().(ed25519.PublicKey))
	if c := checkSignalFeedPinned(body, nil, []string{own}); !c.OK || !c.OwnerKeysPinned || len(c.OwnerSigningKeys) != 1 || c.OwnerSigningKeys[0] != own {
		t.Fatalf("the owner's own key must pass the pin: %+v", c)
	}
	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if c := checkSignalFeedPinned(body, nil, []string{other}); c.OK || !strings.Contains(c.Reason, "not one given with --owner-request-key") {
		t.Fatalf("an owner change signed by a key that was not given must fail: %+v", c)
	}
	if c := checkSignalFeed(body, nil); !c.OK || c.OwnerKeysPinned || len(c.OwnerSigningKeys) != 1 {
		t.Fatalf("without a pin the feed passes and names the signing key: %+v", c)
	}
}

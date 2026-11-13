package main

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 62, N28 (business-records/round-62-n28-behaviour-2026-11-13.md).
// The owner's authority is confirmed from the account's start: its first owner
// key and that key's first request key. Three events start the owner's chain
// afresh: Verdifax clearing the owner key's request key, the owner clearing its
// own, and Verdifax replacing the owner key. A request key registered after any
// of them is unconfirmed until --owner-request-key names it, and so is every
// owner change it signs. An unconfirmed allow never lifts a block; an
// unconfirmed block still counts, since a block only restricts Verdifax. A
// rotation approved by the previous key never breaks the chain.

const n28Owner, n28NewOwner, n28Member = int64(11), int64(13), int64(12)

// n28Base is the account's start: created by Verdifax, its owner key made by
// Verdifax, and the owner's first request key, A, registered at event 3.
func n28Base(t *testing.T) (*feedBuilder, ed25519.PrivateKey, string, ed25519.PrivateKey, string) {
	a, aKey := keyOfSeed("a")
	b, bKey := keyOfSeed("b")
	f := newFeedBuilder(t)
	f.byVerdifax = true
	f.accountChange(artifacts.AccountCreated, 0, "trial")
	f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner, n28Owner)
	f.byVerdifax = false
	f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, aKey, nil)
	return f, a, aKey, b, bKey
}

// verdifaxDoes runs one change as Verdifax.
func verdifaxDoes(f *feedBuilder, change func()) {
	f.byVerdifax = true
	change()
	f.byVerdifax = false
}

func unconfirmedAt(c SignalFeedCheck) []int64 {
	var out []int64
	for _, u := range c.UnconfirmedOwnerChanges {
		out = append(out, u.Sequence)
	}
	return out
}

func sameSequences(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestN28OwnerDecisionsAfterAFreshStartAreUnconfirmed(t *testing.T) {
	deletion := artifacts.AccountSettingVerdifaxDelete
	cases := []struct {
		name        string
		build       func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string)
		pinB        bool
		fails       []string
		unconfirmed []int64
		held        string
	}{
		{"1. an allow from the confirmed key lifts the block, as today", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			f.ownerSetting(deletion, artifacts.SettingAllowed, a)
			verdifaxDoes(f, func() { f.runDeletion(901) })
		}, false, nil, nil, artifacts.SettingAllowed},
		{"2. after Verdifax clears the owner's key, an allow from the new key does not lift the block", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.ownerSetting(deletion, artifacts.SettingAllowed, b)
			verdifaxDoes(f, func() { f.runDeletion(902) })
		}, false, []string{"the allow at event 7", "Verdifax cleared the owner key's request key at event 5", "counts only with --owner-request-key"}, nil, ""},
		{"3. the same feed with the new key named confirms the allow", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.ownerSetting(deletion, artifacts.SettingAllowed, b)
			verdifaxDoes(f, func() { f.runDeletion(903) })
		}, true, nil, nil, artifacts.SettingAllowed},
		{"4. an unconfirmed allow nothing relies on is listed, and the block reads as held", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.ownerSetting(deletion, artifacts.SettingAllowed, b)
		}, false, nil, []int64{7}, artifacts.SettingBlocked},
		{"5. Verdifax clearing the owner's key under a replacement block fails", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(artifacts.AccountSettingOwnerReplace, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
		}, false, []string{"cleared the owner key's request key after the owner blocked owner-key replacement"}, nil, ""},
		{"6. Verdifax clearing a member key's request key is not covered by the owner's block", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			verdifaxDoes(f, func() { f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeRun, n28Member) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Member, bKey, nil)
			f.ownerSetting(artifacts.AccountSettingOwnerReplace, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Member, "", nil) })
		}, false, nil, nil, ""},
		{"7. after the owner clears its own key, an allow from the new key is unconfirmed", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", a)
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.ownerSetting(deletion, artifacts.SettingAllowed, b)
			verdifaxDoes(f, func() { f.runDeletion(904) })
		}, false, []string{"the allow at event 7", "the owner cleared the owner key's request key at event 5", "counts only with --owner-request-key"}, nil, ""},
		{"8. after Verdifax replaces the owner key, an allow from the new owner key is unconfirmed", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() {
				f.keyChangeFor(artifacts.SignalKeyRevoked, artifacts.KeyScopeOwner, n28Owner)
				f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner, n28NewOwner)
			})
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28NewOwner, bKey, nil)
			f.ownerSetting(deletion, artifacts.SettingAllowed, b)
			verdifaxDoes(f, func() { f.runDeletion(905) })
		}, false, []string{"the allow at event 8", "Verdifax replaced the owner key at event 6", "counts only with --owner-request-key"}, nil, ""},
		{"9. a rotation approved by the previous key never breaks the chain", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			f.requestKeyChange(artifacts.AccountRequestKeyRotated, n28Owner, bKey, a)
			f.ownerSetting(deletion, artifacts.SettingAllowed, b)
			verdifaxDoes(f, func() { f.runDeletion(906) })
		}, false, nil, nil, artifacts.SettingAllowed},
		{"11. a rotation approved by an unconfirmed key stays unconfirmed", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			c, cKey := keyOfSeed("c")
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.requestKeyChange(artifacts.AccountRequestKeyRotated, n28Owner, cKey, b)
			f.ownerSetting(deletion, artifacts.SettingAllowed, c)
			verdifaxDoes(f, func() { f.runDeletion(908) })
		}, false, []string{"the allow at event 8", "Verdifax cleared the owner key's request key at event 5", "counts only with --owner-request-key"}, nil, ""},
		{"12. a rotation approved by a confirmed key keeps its standing after a fresh start", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			c, cKey := keyOfSeed("c")
			f.ownerSetting(deletion, artifacts.SettingBlocked, a)
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.requestKeyChange(artifacts.AccountRequestKeyRotated, n28Owner, cKey, b)
			f.ownerSetting(deletion, artifacts.SettingAllowed, c)
			verdifaxDoes(f, func() { f.runDeletion(909) })
		}, true, nil, nil, artifacts.SettingAllowed},
		{"10. a block set by an unconfirmed key still counts", func(f *feedBuilder, a, b ed25519.PrivateKey, bKey string) {
			verdifaxDoes(f, func() { f.requestKeyChange(artifacts.AccountRequestKeyCleared, n28Owner, "", nil) })
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
			f.ownerSetting(deletion, artifacts.SettingBlocked, b)
			verdifaxDoes(f, func() { f.runDeletion(907) })
		}, false, []string{"deleted a record after the owner blocked"}, nil, ""},
	}
	// A failed check reports only its reason, as every failure does: the
	// failing cases name the unconfirmed allow there and list nothing.
	for _, tc := range cases {
		f, a, aKey, b, bKey := n28Base(t)
		tc.build(f, a, b, bKey)
		var pins []string
		if tc.pinB {
			_, cKey := keyOfSeed("c")
			pins = []string{aKey, bKey, cKey}
		}
		c := checkSignalFeedPinned(feedBody(t, f.events), nil, pins)
		if len(tc.fails) == 0 && !c.OK {
			t.Errorf("%s: must verify: %s", tc.name, c.Reason)
			continue
		}
		for _, want := range tc.fails {
			if c.OK || !strings.Contains(c.Reason, want) {
				t.Errorf("%s: must fail naming %q: ok=%v reason=%q", tc.name, want, c.OK, c.Reason)
			}
		}
		if got := unconfirmedAt(c); !sameSequences(got, tc.unconfirmed) {
			t.Errorf("%s: unconfirmed owner changes at %v, want %v", tc.name, got, tc.unconfirmed)
		}
		if tc.held != "" && c.OwnerBlocks[deletion] != tc.held {
			t.Errorf("%s: the deletion block reads %q, want %q", tc.name, c.OwnerBlocks[deletion], tc.held)
		}
	}
}

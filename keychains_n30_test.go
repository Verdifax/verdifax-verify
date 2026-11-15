package main

import (
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 62, N30: an account made before registrations were sealed can show
// owner changes signed by a key the feed never registered. The first
// registration after them starts the owner's chain afresh, so a key planted
// then is unconfirmed until --owner-request-key names it.

func n30Feed(t *testing.T) (*feedBuilder, string) {
	a, _ := keyOfSeed("a")
	b, bKey := keyOfSeed("b")
	f := newFeedBuilder(t)
	f.byVerdifax = true
	f.accountChange(artifacts.AccountCreated, 0, "trial")
	f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner, n28Owner)
	f.byVerdifax = false
	// The owner blocks Verdifax deletion with a key this feed never registered.
	f.ownerSetting(artifacts.AccountSettingVerdifaxDelete, artifacts.SettingBlocked, a)
	// The first sealed registration, then an allow it signs, then a deletion.
	f.requestKeyChange(artifacts.AccountRequestKeyRegistered, n28Owner, bKey, nil)
	f.ownerSetting(artifacts.AccountSettingVerdifaxDelete, artifacts.SettingAllowed, b)
	verdifaxDoes(f, func() { f.runDeletion(931) })
	return f, bKey
}

func TestN30FirstRegistrationAfterUnregisteredOwnerChangesIsAFreshStart(t *testing.T) {
	f, bKey := n30Feed(t)
	c := checkSignalFeedPinned(feedBody(t, f.events), nil, nil)
	if c.OK || !strings.Contains(c.Reason, freshStartUnsealed) || !strings.Contains(c.Reason, "counts only with --owner-request-key") {
		t.Fatalf("the allow signed by the first registered key, after unregistered owner changes, must count only when pinned: ok=%v reason=%q", c.OK, c.Reason)
	}
	_ = bKey
}

func TestN30PinnedKeyConfirmsTheAllow(t *testing.T) {
	f, bKey := n30Feed(t)
	_, aKey := keyOfSeed("a")
	if c := checkSignalFeedPinned(feedBody(t, f.events), nil, []string{aKey, bKey}); !c.OK {
		t.Fatalf("with the owner's keys pinned the feed must verify: %s", c.Reason)
	}
}

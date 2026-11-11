package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// interruptedRecord closes place on chain with a sealed, anchored record, as
// the server's sweep does (round 57, N2).
func (f *feedBuilder) interruptedRecord(chain, recordKind string, place int64) artifacts.ChainInterrupted {
	link, at := f.next()
	c := artifacts.ChainInterrupted{Format: artifacts.ChainInterruptedFormat, Chain: chain, Place: place, RecordKind: recordKind,
		PlannedRecordHash: strings.Repeat("8", 64), PlannedLeaf: strings.Repeat("9", 64), RecordedAt: at.Format(time.RFC3339Nano), Signal: link}
	c.InterruptedHash = c.ComputeHash()
	c.Anchor = f.anchor(artifacts.ChainInterruptedKind, c.InterruptedHash, c.LeafHash(), at)
	f.add(artifacts.SignalChainInterrupted, link, c.InterruptedHash, 0, c)
	return c
}

// Round 57, N2: a sign-off history skips one place only through a sealed,
// anchored interrupted record that closes exactly that place, in the same
// account; the report names it. Every other skip fails.
func TestASignOffHistorySkipsAPlaceOnlyThroughAnInterruptedRecord(t *testing.T) {
	f := newFeedBuilder(t)
	first := f.signOffAt(1, artifacts.NoPreviousSignOff)
	closed := f.interruptedRecord(artifacts.GapChainSignOffs, artifacts.SignOffKind, 2)
	after := f.signOffAt(3, first.SignOffHash)
	c := checkSignOffHistory(encode(t, []any{first, closed, after}))
	if !c.OK || len(c.Entries) != 2 || len(c.Gaps) != 1 || !strings.Contains(c.Gaps[0], "never confirmed") {
		t.Fatalf("a history with an interrupted record must verify and name it: %+v", c)
	}
	if c := checkSignOffHistory(encode(t, []any{first, after})); c.OK {
		t.Fatalf("the same skip with no record must fail: %+v", c)
	}
	wrongPlace := f.interruptedRecord(artifacts.GapChainSignOffs, artifacts.SignOffKind, 3)
	if c := checkSignOffHistory(encode(t, []any{first, wrongPlace, after})); c.OK || !strings.Contains(c.Reason, "next place is 2") {
		t.Fatalf("a record closing another place must fail: %+v", c)
	}
	unanchored := closed
	unanchored.Anchor = nil
	if c := checkSignOffHistory(encode(t, []any{first, unanchored, after})); c.OK {
		t.Fatalf("a record that is not on the public log must fail: %+v", c)
	}
	other := closed
	other.Signal.Account = "account-99"
	other.InterruptedHash = other.ComputeHash()
	if c := checkSignOffHistory(encode(t, []any{first, other, after})); c.OK {
		t.Fatalf("another account's record must not excuse a skip: %+v", c)
	}
}

// A policy history skips a place only through an interrupted record of the
// same chain.
func TestAPolicyHistorySkipsAPlaceOnlyThroughAnInterruptedRecord(t *testing.T) {
	f := newFeedBuilder(t)
	first := f.activationAt(1, artifacts.NoPreviousActivation)
	closed := f.interruptedRecord(artifacts.GapChainAccountPolicy, artifacts.PolicyActivationKind, 2)
	after := f.activationAt(3, first.ActivationHash)
	if c := checkPolicyHistory(encode(t, []any{first, closed, after})); !c.OK || len(c.Gaps) != 1 {
		t.Fatalf("a history with an interrupted record must verify and name it: %+v", c)
	}
	signOffs := f.interruptedRecord(artifacts.GapChainSignOffs, artifacts.SignOffKind, 2)
	if c := checkPolicyHistory(encode(t, []any{first, signOffs, after})); c.OK || !strings.Contains(c.Reason, "not of this one") {
		t.Fatalf("another chain's record must not excuse a skip: %+v", c)
	}
}

// The feed carries the interrupted record as its own event, checked like
// every other account record.
func TestAnInterruptedRecordsEventVerifies(t *testing.T) {
	f := newFeedBuilder(t)
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	f.signOffAt(1, artifacts.NoPreviousSignOff)
	f.interruptedRecord(artifacts.GapChainSignOffs, artifacts.SignOffKind, 2)
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || len(c.Entries) != 3 || c.Entries[2].Kind != artifacts.SignalChainInterrupted {
		t.Fatalf("the feed with an interrupted record must verify: %+v", c)
	}
}

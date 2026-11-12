package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// runSealed adds a successful run's event (round 56, E5).
func (f *feedBuilder) runSealed() {
	link, at := f.next()
	f.runID++
	r := artifacts.RunSealed{Format: artifacts.RunSealedFormat, RunID: f.runID, RecordHash: strings.Repeat("7", 64),
		SealedAt: at.Format(time.RFC3339Nano), Signal: link}
	r.RunSealedHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.RunSealedKind, r.RunSealedHash, r.LeafHash(), at)
	f.add(artifacts.SignalRunSealed, link, r.RunSealedHash, f.runID, r)
}

// runSealedRequiringSignOff adds a successful run's event whose allowing rule
// requires a person's sign-off (round 59 batch, B7). With dropped, the entry
// leaves signoff_required out after it was sealed, as a forger would.
func (f *feedBuilder) runSealedRequiringSignOff(dropped bool) {
	link, at := f.next()
	f.runID++
	r := artifacts.RunSealed{Format: artifacts.RunSealedFormat, RunID: f.runID, RecordHash: strings.Repeat("7", 64),
		SealedAt: at.Format(time.RFC3339Nano), SignOffRequired: true, Signal: link}
	r.RunSealedHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.RunSealedKind, r.RunSealedHash, r.LeafHash(), at)
	if dropped {
		r.SignOffRequired = false
	}
	f.add(artifacts.SignalRunSealed, link, r.RunSealedHash, f.runID, r)
}

// gap adds a restore gap on chain, skipping places from lostFrom to lostTo,
// at the feed place seq (round 56, E4).
func (f *feedBuilder) gap(chain string, lostFrom, lostTo, seq int64) {
	at := feedStart.Add(time.Duration(seq) * time.Minute)
	link := artifacts.SignalLink{Account: feedAccount, Sequence: seq, PreviousSignalHash: f.previous}
	g := artifacts.RestoreGap{Format: artifacts.RestoreGapFormat, Chain: chain, LostFrom: lostFrom, LostTo: lostTo,
		RecordedAt: at.Format(time.RFC3339Nano), Signal: link}
	g.RestoreGapHash = g.ComputeHash()
	g.Anchor = f.anchor(artifacts.RestoreGapKind, g.RestoreGapHash, g.LeafHash(), at)
	f.add(artifacts.SignalChainGap, link, g.RestoreGapHash, 0, g)
}

// A successful run is an event whose sealed entry names its run, checked
// like every other account record.
func TestASuccessfulRunsEventVerifies(t *testing.T) {
	f := newFeedBuilder(t)
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	f.runSealed()
	f.runSealed()
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || len(c.Entries) != 3 || c.Entries[1].Kind != artifacts.SignalRunSealed || c.Entries[1].RunID == 0 {
		t.Fatalf("%+v", c)
	}
}

// A successful run whose rule requires a sign-off says so in its sealed
// entry; an entry with the requirement left out after sealing fails.
func TestASuccessfulRunsEventSealsASignOffRequirement(t *testing.T) {
	f := newFeedBuilder(t)
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	f.runSealedRequiringSignOff(false)
	if c := checkSignalFeed(feedBody(t, f.events), nil); !c.OK || len(c.Entries) != 2 {
		t.Fatalf("a run that requires a sign-off: %+v", c)
	}
	g := newFeedBuilder(t)
	g.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	g.runSealedRequiringSignOff(true)
	if c := checkSignalFeed(feedBody(t, g.events), nil); c.OK {
		t.Fatal("an entry with its sign-off requirement left out passed")
	}
}

// After a restore, the feed skips the places it may have lost only through a
// sealed restore gap that names exactly those places; the verifier reports
// the gap. Any other jump fails.
func TestAFeedSkipsPlacesOnlyThroughADeclaredRestoreGap(t *testing.T) {
	f := newFeedBuilder(t)
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	f.runSealed()
	f.gap(artifacts.GapChainSignals, 3, 102, 103)
	// The sign-off chain's gap takes the feed's next place.
	f.gap(artifacts.GapChainSignOffs, 2, 101, 104)
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || c.DeclaredGaps != 2 || c.Last != 104 {
		t.Fatalf("a feed with declared gaps must verify and report them: %+v", c)
	}
	if e := c.Entries[2]; e.GapChain != artifacts.GapChainSignals || e.GapFrom != 3 || e.GapTo != 102 {
		t.Fatalf("the feed's gap must be reported with its places: %+v", e)
	}

	// The same jump with no gap.
	g := newFeedBuilder(t)
	g.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	g.runSealed()
	link := artifacts.SignalLink{Account: feedAccount, Sequence: 103, PreviousSignalHash: g.previous}
	k := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, DecidedBy: artifacts.DecidedByOwner, Action: artifacts.SignalKeyRevoked, KeyID: 77, KeyScope: artifacts.KeyScopeRun,
		Name: "member", ChangedAt: feedStart.Add(103 * time.Minute).Format(time.RFC3339Nano), Signal: link}
	k.KeyChangeHash = k.ComputeHash()
	k.Anchor = g.anchor(artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), feedStart.Add(103*time.Minute))
	g.add(artifacts.SignalKeyRevoked, link, k.KeyChangeHash, 0, k)
	if c := checkSignalFeed(feedBody(t, g.events), nil); c.OK || !strings.Contains(c.Reason, "missing or out of order") {
		t.Fatalf("a jump with no declared gap must fail: %+v", c)
	}

	// A gap that names other places than it skips.
	h := newFeedBuilder(t)
	h.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	h.gap(artifacts.GapChainSignals, 2, 50, 103)
	if c := checkSignalFeed(feedBody(t, h.events), nil); c.OK {
		t.Fatalf("a gap that does not end right before its own place must fail: %+v", c)
	}
	i := newFeedBuilder(t)
	i.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	i.gap(artifacts.GapChainSignals, 5, 102, 103)
	if c := checkSignalFeed(feedBody(t, i.events), nil); c.OK || !strings.Contains(c.Reason, "not the places between") {
		t.Fatalf("a gap that does not start right after the event before it must fail: %+v", c)
	}
}

// signOffAt makes a sign-off at a place in the account's sign-off chain, with
// a place in the feed, anchored.
func (f *feedBuilder) signOffAt(seq int64, previous string) artifacts.SignOff {
	link, at := f.next()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	s := artifacts.SignOff{Format: artifacts.SignOffFormat, ChainID: feedAccount, Sequence: seq, PreviousSignOffHash: previous,
		Target:   artifacts.SignOffTarget{Kind: artifacts.SignOffTargetReceipt, RunID: 900, Digest: strings.Repeat("6", 64)},
		Decision: artifacts.SignOffApprove, ApproverKey: base64.StdEncoding.EncodeToString(pub), SignedAt: at.Format(time.RFC3339),
		Nonce: strings.Repeat("0", 32), RecordedAt: at.Format(time.RFC3339), Signal: &link}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, s.Preimage()))
	s.SignOffHash = s.ComputeHash()
	s.Anchor = f.anchor(artifacts.SignOffKind, s.SignOffHash, s.LeafHash(), at)
	f.add(artifacts.SignalSignOffRecorded, link, s.SignOffHash, 900, s)
	return s
}

// gapRecord is a restore gap on chain at the feed's next place.
func (f *feedBuilder) gapRecord(chain string, lostFrom, lostTo int64) artifacts.RestoreGap {
	link, at := f.next()
	g := artifacts.RestoreGap{Format: artifacts.RestoreGapFormat, Chain: chain, LostFrom: lostFrom, LostTo: lostTo,
		RecordedAt: at.Format(time.RFC3339Nano), Signal: link}
	g.RestoreGapHash = g.ComputeHash()
	g.Anchor = f.anchor(artifacts.RestoreGapKind, g.RestoreGapHash, g.LeafHash(), at)
	f.add(artifacts.SignalChainGap, link, g.RestoreGapHash, 0, g)
	return g
}

// A sign-off history skips places only through a sealed restore gap in its
// place, which the report lists.
func TestASignOffHistorySkipsPlacesOnlyThroughADeclaredGap(t *testing.T) {
	f := newFeedBuilder(t)
	first := f.signOffAt(1, artifacts.NoPreviousSignOff)
	gap := f.gapRecord(artifacts.GapChainSignOffs, 2, 101)
	after := f.signOffAt(102, first.SignOffHash)
	c := checkSignOffHistory(encode(t, []any{first, gap, after}))
	if !c.OK || len(c.Entries) != 2 || len(c.Gaps) != 1 {
		t.Fatalf("a history with a declared gap must verify and list it: %+v", c)
	}
	if c := checkSignOffHistory(encode(t, []any{first, after})); c.OK || !strings.Contains(c.Reason, "missing or out of order") {
		t.Fatalf("the same jump with no gap must fail: %+v", c)
	}
	early := f.gapRecord(artifacts.GapChainSignOffs, 3, 101)
	if c := checkSignOffHistory(encode(t, []any{first, early, after})); c.OK || !strings.Contains(c.Reason, "next place is 2") {
		t.Fatalf("a gap that does not start at the chain's next place must fail: %+v", c)
	}
	feedOnly := f.gapRecord(artifacts.GapChainSignals, 1, 1)
	if c := checkSignOffHistory(encode(t, []any{first, feedOnly, after})); c.OK {
		t.Fatalf("another chain's gap must not excuse a jump: %+v", c)
	}
}

// activationAt makes an account policy change at a place in its chain.
func (f *feedBuilder) activationAt(seq int64, previous string) artifacts.PolicyActivation {
	link, at := f.next()
	a := artifacts.PolicyActivation{Format: artifacts.PolicyActivationFormat, ChainID: feedAccount, Sequence: seq,
		PreviousActivationHash: previous, PolicyID: "p", PolicyVersion: strconv.FormatInt(seq, 10), PolicyHash: strings.Repeat("4", 64),
		DocumentHash: strings.Repeat("5", 64), ActivatedAt: at.Format(time.RFC3339Nano), Signal: &link}
	a.ActivationHash = a.ComputeHash()
	a.Anchor = f.anchor(artifacts.PolicyActivationKind, a.ActivationHash, a.LeafHash(), at)
	f.add(artifacts.SignalPolicyChanged, link, a.ActivationHash, 0, a)
	return a
}

// A policy history skips places only through a sealed restore gap of the
// same chain.
func TestAPolicyHistorySkipsPlacesOnlyThroughADeclaredGap(t *testing.T) {
	f := newFeedBuilder(t)
	first := f.activationAt(1, artifacts.NoPreviousActivation)
	gap := f.gapRecord(artifacts.GapChainAccountPolicy, 2, 101)
	after := f.activationAt(102, first.ActivationHash)
	c := checkPolicyHistory(encode(t, []any{first, gap, after}))
	if !c.OK || len(c.Entries) != 2 || len(c.Gaps) != 1 {
		t.Fatalf("a history with a declared gap must verify and list it: %+v", c)
	}
	if c := checkPolicyHistory(encode(t, []any{first, after})); c.OK {
		t.Fatalf("the same jump with no gap must fail: %+v", c)
	}
	signOffGap := f.gapRecord(artifacts.GapChainSignOffs, 2, 101)
	if c := checkPolicyHistory(encode(t, []any{first, signOffGap, after})); c.OK || !strings.Contains(c.Reason, "not of this one") {
		t.Fatalf("another chain's gap must not excuse a jump: %+v", c)
	}
}

// A reader whose saved point is an event a restore lost is told so: the
// check fails and names the gap, the events it holds are the evidence.
func TestAPointInsideARestoreGapIsNamed(t *testing.T) {
	f := newFeedBuilder(t)
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	f.runSealed()
	f.gap(artifacts.GapChainSignals, 3, 102, 103)
	page := feedBody(t, f.events[2:])
	c := checkSignalFeed(page, &signalPoint{sequence: 3, hash: strings.Repeat("9", 64)})
	if c.OK || !strings.Contains(c.Reason, "your point, event 3, is inside a restore gap that skips places 3 to 102") ||
		!strings.Contains(c.Reason, "from event 2") {
		t.Fatalf("a point inside a gap must be named: %+v", c)
	}
	if c := checkSignalFeed(page, &signalPoint{sequence: 2, hash: f.events[1].Data.EventHash}); !c.OK {
		t.Fatalf("from the event before the gap the page continues: %+v", c)
	}
}

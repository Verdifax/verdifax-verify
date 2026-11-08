package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

const feedAccount = "account-7"

// feedStart is after every receipt cutover, so receipts must be anchored.
var feedStart = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// feedBuilder makes an account's feed as the server does: each entry seals its
// place before it is logged, and each event names the one before.
type feedBuilder struct {
	t        *testing.T
	l        *testLog
	events   []signalCloudEvent
	previous string
	runID    int64
}

func newFeedBuilder(t *testing.T) *feedBuilder {
	l := newTestLog(t)
	l.install(t)
	return &feedBuilder{t: t, l: l, previous: artifacts.NoPreviousSignal, runID: 900}
}

func (f *feedBuilder) next() (artifacts.SignalLink, time.Time) {
	seq := int64(len(f.events) + 1)
	return artifacts.SignalLink{Account: feedAccount, Sequence: seq, PreviousSignalHash: f.previous},
		feedStart.Add(time.Duration(seq) * time.Minute)
}

func (f *feedBuilder) anchor(kind, hash, leaf string, at time.Time) *artifacts.ReceiptAnchor {
	f.l.integratedTime = at.Add(20 * time.Second).Unix()
	e := f.l.entry(f.t, strings.Repeat("0", 64), leaf)
	return &artifacts.ReceiptAnchor{Kind: artifacts.ReceiptAnchorKindV3, ReceiptKind: kind, ReceiptHash: hash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex, LogIndex: e.LogIndex, TreeSize: e.TreeSize,
		RootHashHex: e.RootHashHex, InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime, EntryBody: e.EntryBody}
}

func (f *feedBuilder) add(kind string, link artifacts.SignalLink, entryHash string, runID int64, entry any) {
	raw, err := json.Marshal(entry)
	if err != nil {
		f.t.Fatal(err)
	}
	eventHash := artifacts.SignalEventHash(kind, entryHash, link)
	f.events = append(f.events, signalCloudEvent{SpecVersion: "1.0", ID: feedAccount + "/" + strconv.FormatInt(link.Sequence, 10),
		Source: signalSource + feedAccount, Type: artifacts.SignalTypePrefix + kind, Time: feedStart.Format(time.RFC3339),
		DataContentType: "application/json",
		Data: signalEvent{Form: artifacts.SignalFormat, Kind: kind, Account: feedAccount, Sequence: link.Sequence,
			PreviousSignalHash: link.PreviousSignalHash, EventHash: eventHash, RunID: runID, Entry: raw}})
	f.previous = eventHash
}

// failedRun adds a run that failed with a server error.
func (f *feedBuilder) failedRun() {
	link, at := f.next()
	f.runID++
	r := &artifacts.FailureReceipt{AnchorRequired: true, EnvelopeID: "env-" + strconv.FormatInt(f.runID, 10), ErrorClass: artifacts.FailureInternal,
		EvaluatorVersion: "pipeline-1.0.0", FailClock: at.Format(time.RFC3339Nano), FailedStage: "stage_7", Version: artifacts.FailureReceiptVersion}
	if _, err := artifacts.BuildFailureReceiptHash(r); err != nil {
		f.t.Fatal(err)
	}
	ctx := &artifacts.ReceiptContext{Request: artifacts.SealedRequestFields{PayloadHash: strings.Repeat("1", 64), ProgramID: strings.Repeat("2", 64),
		RouteID: "route-a", RegistryRecordHash: strings.Repeat("3", 64)}, AccountID: feedAccount, Signal: &link}
	leaf := artifacts.ComputeReceiptLeafHashV3("failure_receipt", r.EnvelopeID, r.Hash, f.runID, ctx.Hash())
	doc := artifacts.ReceiptDocument{OK: true, RunID: f.runID, FailureReceipt: r, ReceiptContext: ctx,
		ReceiptAnchor: f.anchor("failure_receipt", r.Hash, leaf, at)}
	f.add(artifacts.SignalRunFailed, link, r.Hash, f.runID, doc)
}

// policyChange adds an account policy change.
func (f *feedBuilder) policyChange() {
	link, at := f.next()
	a := artifacts.PolicyActivation{Format: artifacts.PolicyActivationFormat, ChainID: feedAccount, Sequence: 1,
		PreviousActivationHash: artifacts.NoPreviousActivation, PolicyID: "p", PolicyVersion: "1", PolicyHash: strings.Repeat("4", 64),
		DocumentHash: strings.Repeat("5", 64), ActivatedAt: at.Format(time.RFC3339Nano), Signal: &link}
	a.ActivationHash = a.ComputeHash()
	a.Anchor = f.anchor(artifacts.PolicyActivationKind, a.ActivationHash, a.LeafHash(), at)
	f.add(artifacts.SignalPolicyChanged, link, a.ActivationHash, 0, a)
}

// signOff adds a sign-off on the last failed run.
func (f *feedBuilder) signOff() {
	link, at := f.next()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	s := artifacts.SignOff{Format: artifacts.SignOffFormat, ChainID: feedAccount, Sequence: 1, PreviousSignOffHash: artifacts.NoPreviousSignOff,
		Target:   artifacts.SignOffTarget{Kind: artifacts.SignOffTargetReceipt, RunID: f.runID, Digest: strings.Repeat("6", 64)},
		Decision: artifacts.SignOffReject, ApproverKey: base64.StdEncoding.EncodeToString(pub), SignedAt: at.Format(time.RFC3339),
		Nonce: strings.Repeat("0", 32), RecordedAt: at.Format(time.RFC3339), Signal: &link}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, s.Preimage()))
	s.SignOffHash = s.ComputeHash()
	s.Anchor = f.anchor(artifacts.SignOffKind, s.SignOffHash, s.LeafHash(), at)
	f.add(artifacts.SignalSignOffRecorded, link, s.SignOffHash, f.runID, s)
}

// keyChange adds a key created or revoked.
func (f *feedBuilder) keyChange(action, scope string) {
	link, at := f.next()
	k := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, Action: action, KeyID: 40 + link.Sequence, KeyScope: scope,
		Name: "feed reader", ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	if scope == artifacts.KeyScopeApprover {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		k.PublicKey = base64.StdEncoding.EncodeToString(pub)
	}
	k.KeyChangeHash = k.ComputeHash()
	k.Anchor = f.anchor(artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), at)
	f.add(action, link, k.KeyChangeHash, 0, k)
}

func (f *feedBuilder) full() []signalCloudEvent {
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	f.failedRun()
	f.policyChange()
	f.signOff()
	f.keyChange(artifacts.SignalApproverRegistered, artifacts.KeyScopeApprover)
	f.keyChange(artifacts.SignalKeyRevoked, artifacts.KeyScopeRun)
	return f.events
}

func feedBody(t *testing.T, events []signalCloudEvent) []byte {
	t.Helper()
	return encode(t, signalFeedPage{Events: events, NextAfter: int64(len(events)), Newest: int64(len(events))})
}

func TestAFullFeedVerifiesFromTheStart(t *testing.T) {
	f := newFeedBuilder(t)
	events := f.full()
	c := checkSignalFeed(feedBody(t, events), nil)
	if !c.OK || c.ContinuityFrom != "start" || c.First != 1 || c.Last != 6 || len(c.Entries) != 6 || c.Account != feedAccount {
		t.Fatalf("%+v", c)
	}
	if c.Entries[1].Kind != artifacts.SignalRunFailed || c.Entries[1].RunID == 0 {
		t.Fatalf("the failed run is not reported: %+v", c.Entries[1])
	}
	printSignalFeed(&c)
	// A bare list of events reads the same.
	if bare := checkSignalFeed(encode(t, events), nil); !bare.OK {
		t.Fatalf("a bare list failed: %s", bare.Reason)
	}
}

func TestAFeedContinuesFromAGivenPoint(t *testing.T) {
	f := newFeedBuilder(t)
	events := f.full()
	first := checkSignalFeed(feedBody(t, events[:3]), nil)
	if !first.OK {
		t.Fatal(first.Reason)
	}
	point := &signalPoint{first.Last, first.LastEventHash}
	if c := checkSignalFeed(feedBody(t, events[3:]), point); !c.OK || c.ContinuityFrom != "given point" {
		t.Fatalf("%+v", c)
	}
	// From a wrong point, or with no point, the continuation is not shown.
	if c := checkSignalFeed(feedBody(t, events[4:]), point); c.OK {
		t.Fatal("a page skipping an event passed against the point")
	}
	if c := checkSignalFeed(feedBody(t, events[3:]), &signalPoint{3, strings.Repeat("a", 64)}); c.OK {
		t.Fatal("a page passed against a wrong point")
	}
	if c := checkSignalFeed(feedBody(t, events[3:]), nil); !c.OK || c.ContinuityFrom != "not checked" {
		t.Fatalf("a later page with no point must pass and say continuity was not checked: %+v", c)
	}
}

// Removing, reordering or rewriting any event fails.
func TestAnAlteredFeedFails(t *testing.T) {
	f := newFeedBuilder(t)
	events := f.full()
	cases := map[string]func() []signalCloudEvent{
		"an event removed": func() []signalCloudEvent {
			return append(append([]signalCloudEvent{}, events[:2]...), events[3:]...)
		},
		"two events swapped": func() []signalCloudEvent {
			out := append([]signalCloudEvent{}, events...)
			out[2], out[3] = out[3], out[2]
			return out
		},
		"the first event removed": func() []signalCloudEvent {
			return append([]signalCloudEvent{}, events[1:]...)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			got := build()
			point := (*signalPoint)(nil)
			if name == "the first event removed" {
				point = &signalPoint{0, artifacts.NoPreviousSignal}
			}
			if c := checkSignalFeed(feedBody(t, got), point); c.OK {
				t.Fatalf("passed: %+v", c)
			}
		})
	}
	edits := map[string]func(e *signalCloudEvent){
		"the kind": func(e *signalCloudEvent) {
			e.Data.Kind = artifacts.SignalRunHalted
			e.Type = artifacts.SignalTypePrefix + e.Data.Kind
		},
		"the type":       func(e *signalCloudEvent) { e.Type = "com.verdifax.run.halted" },
		"the run":        func(e *signalCloudEvent) { e.Data.RunID++ },
		"the event hash": func(e *signalCloudEvent) { e.Data.EventHash = strings.Repeat("b", 64) },
		"the account": func(e *signalCloudEvent) {
			e.Data.Account = "account-8"
			e.Source = signalSource + "account-8"
			e.ID = "account-8/2"
		},
		"the source":       func(e *signalCloudEvent) { e.Source = signalSource + "account-8" },
		"the id":           func(e *signalCloudEvent) { e.ID = feedAccount + "/9" },
		"the specversion":  func(e *signalCloudEvent) { e.SpecVersion = "0.3" },
		"the form":         func(e *signalCloudEvent) { e.Data.Form = "verdifax.signal.v0" },
		"the content type": func(e *signalCloudEvent) { e.DataContentType = "text/plain" },
		"the entry's stage": func(e *signalCloudEvent) {
			e.Data.Entry = json.RawMessage(strings.Replace(string(e.Data.Entry), "stage_7", "stage_8", 1))
		},
	}
	for name, edit := range edits {
		t.Run("rewriting "+name, func(t *testing.T) {
			got := append([]signalCloudEvent{}, events...)
			edit(&got[1])
			if c := checkSignalFeed(feedBody(t, got), nil); c.OK {
				t.Fatalf("passed: %+v", c)
			}
		})
	}
}

// Every entry kind must seal the event's own place.
func TestAnEntryThatSealsAnotherPlaceFails(t *testing.T) {
	a := newFeedBuilder(t)
	a.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeSignals)
	a.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeRun)
	// Swap the second event's entry for one sealing place 1.
	events := a.events
	events[1].Data.Entry = events[0].Data.Entry
	if c := checkSignalFeed(feedBody(t, events), nil); c.OK {
		t.Fatal("an entry sealing another place passed")
	}
}

func TestAFeedOfTwoAccountsOrUnknownFieldsFails(t *testing.T) {
	f := newFeedBuilder(t)
	events := f.full()
	body := strings.Replace(string(feedBody(t, events)), `"specversion"`, `"extra":1,"specversion"`, 1)
	if c := checkSignalFeed([]byte(body), nil); c.OK {
		t.Fatal("an unknown field passed")
	}
	if c := checkSignalFeed([]byte(`{"events":[]}`), nil); c.OK {
		t.Fatal("an empty feed passed")
	}
}

func TestSignalPointsParse(t *testing.T) {
	if p, err := parseSignalPoint("3:" + strings.Repeat("a", 64)); err != nil || p.sequence != 3 {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"3", "x:" + strings.Repeat("a", 64), "3:" + strings.Repeat("A", 64), "0:" + strings.Repeat("a", 64),
		"3:" + artifacts.NoPreviousSignal, "-1:" + strings.Repeat("a", 64)} {
		if _, err := parseSignalPoint(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// A receipt verified alone checks its sealed place too.
func TestAReceiptsSealedPlaceIsChecked(t *testing.T) {
	f := newFeedBuilder(t)
	f.failedRun()
	var doc artifacts.ReceiptDocument
	if err := json.Unmarshal(f.events[0].Data.Entry, &doc); err != nil {
		t.Fatal(err)
	}
	if rep := verifyReceiptDocument(&doc); !rep.AllPassed || rep.SignalSequence != 1 || rep.ReceiptKind != "failure_receipt" {
		t.Fatalf("%+v", rep)
	}
	doc.ReceiptContext.Signal.Sequence = 2
	if rep := verifyReceiptDocument(&doc); rep.AllPassed {
		t.Fatal("a receipt whose sealed place was changed passed")
	}
}

func TestKeyChangesAndFailureReceiptsValidate(t *testing.T) {
	link := artifacts.SignalLink{Account: feedAccount, Sequence: 1, PreviousSignalHash: artifacts.NoPreviousSignal}
	good := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, Action: artifacts.SignalKeyCreated, KeyID: 4, KeyScope: artifacts.KeyScopeSignals,
		Name: "n", ChangedAt: feedStart.Format(time.RFC3339), Signal: link}
	good.KeyChangeHash = good.ComputeHash()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(k *artifacts.KeyChange){
		"approver action on a run key": func(k *artifacts.KeyChange) { k.Action = artifacts.SignalApproverRegistered },
		"public key on a feed key":     func(k *artifacts.KeyChange) { k.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"unknown scope":                func(k *artifacts.KeyChange) { k.KeyScope = "admin" },
		"unknown action":               func(k *artifacts.KeyChange) { k.Action = "key.renamed" },
		"zero key":                     func(k *artifacts.KeyChange) { k.KeyID = 0 },
		"bad link":                     func(k *artifacts.KeyChange) { k.Signal.Sequence = 2 },
	} {
		k := good
		edit(&k)
		if k.Validate() == nil {
			t.Errorf("%s validated", name)
		}
	}
	sealed := artifacts.FailureReceipt{EnvelopeID: "e", ErrorClass: artifacts.FailureTimeout, FailedStage: "stage_7", Version: artifacts.FailureReceiptVersion}
	if _, err := artifacts.BuildFailureReceiptHash(&sealed); err != nil || artifacts.VerifyFailureReceiptHash(&sealed) != nil {
		t.Fatalf("a sealed failure receipt does not verify: %v", err)
	}
	sealed.FailedStage = "stage_8"
	if artifacts.VerifyFailureReceiptHash(&sealed) == nil {
		t.Fatal("a failure receipt with a changed stage verified")
	}
	for _, kind := range artifacts.SignalKinds {
		if !artifacts.IsSignalKind(kind) {
			t.Fatalf("%s is not a signal kind", kind)
		}
	}
	if artifacts.IsSignalKind("run.paused") || artifacts.IsSignalKind("") {
		t.Fatal("an unknown kind reads as a signal kind")
	}
	for name, r := range map[string]artifacts.FailureReceipt{
		"unknown class": {EnvelopeID: "e", ErrorClass: "oops", FailedStage: "s", Version: artifacts.FailureReceiptVersion},
		"stage text":    {EnvelopeID: "e", ErrorClass: artifacts.FailureTimeout, FailedStage: "Stage 7: panic", Version: artifacts.FailureReceiptVersion},
		"version":       {EnvelopeID: "e", ErrorClass: artifacts.FailureTimeout, FailedStage: "s", Version: "v0"},
	} {
		if _, err := artifacts.BuildFailureReceiptHash(&r); err == nil {
			t.Errorf("%s built", name)
		}
	}
}
